#!/usr/bin/env bash
# One-command deploy to Cloud Run, authenticated only.
#
#   ./deploy.sh --project my-gcp-project
#
# Does everything end to end (idempotent, safe to re-run):
#   1. Enables the APIs, creates the KMS key, wrapped DLP key and Model Armor templates (scripts/bootstrap_gcp.sh)
#   2. Creates a least-privilege runtime service account
#   3. Stores a random vault key in Secret Manager
#   4. Builds from source and deploys to Cloud Run behind IAP (Google sign-in)
#   5. Grants IAP access to you (or to --iap-user)
#
# Flags:
#   --project ID        GCP project (default: $GOOGLE_CLOUD_PROJECT, then gcloud config)
#   --region REGION     Cloud Run region (default: us-central1)
#   --service NAME      Cloud Run service name (default: secure-id-extract)
#   --iap-user EMAIL    grant IAP access to this user (repeatable; default: current gcloud account)
#   --no-iap            no IAP: callers need roles/run.invoker and an ID token
#   --dry-run           print the commands instead of running them
# There is intentionally no option for unauthenticated access.
set -euo pipefail
cd "$(dirname "$0")"

PROJECT="${GOOGLE_CLOUD_PROJECT:-}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-secure-id-extract}"
USE_IAP=1
DRY=""
USERS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT="$2"; shift ;;
    --region) REGION="$2"; shift ;;
    --service) SERVICE="$2"; shift ;;
    --iap-user) USERS+=("$2"); shift ;;
    --no-iap) USE_IAP=0 ;;
    --dry-run) DRY=1 ;;
    -h|--help) sed -n '2,21p' "$0"; exit 0 ;;
    *) echo "Unknown flag $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done
if [[ -z "$PROJECT" ]]; then
  PROJECT="$(gcloud config get-value project 2>/dev/null || true)"
fi
if [[ -z "$PROJECT" ]]; then
  echo "No project. Use --project <PROJECT_ID>." >&2
  exit 1
fi
if [[ ${#USERS[@]} -eq 0 ]]; then
  USERS=("$(gcloud config get-value account 2>/dev/null)")
fi

run() { if [[ -n "$DRY" ]]; then echo "+ $*" >&2; else "$@"; fi; }

echo "== 1/5 Bootstrap security resources in ${PROJECT}"
if [[ -f .env.local ]] && grep -q "^GOOGLE_CLOUD_PROJECT=${PROJECT}$" .env.local; then
  echo "Using existing .env.local for ${PROJECT}"
else
  run env GOOGLE_CLOUD_PROJECT="$PROJECT" ./scripts/bootstrap_gcp.sh
fi
if [[ -z "$DRY" || -f .env.local ]]; then
  # shellcheck disable=SC1091
  source .env.local
fi
run gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com \
  secretmanager.googleapis.com iap.googleapis.com --project "$PROJECT"

SA_NAME="${SERVICE}-sa"
SA="${SA_NAME}@${PROJECT}.iam.gserviceaccount.com"
SECRET="${SERVICE}-vault-key"

echo "== 2/5 Runtime service account ${SA}"
gcloud iam service-accounts describe "$SA" --project "$PROJECT" >/dev/null 2>&1 \
  || run gcloud iam service-accounts create "$SA_NAME" --project "$PROJECT" --display-name "Secure ID Extract runtime"
for role in roles/aiplatform.user roles/modelarmor.user roles/modelarmor.viewer roles/dlp.user roles/serviceusage.serviceUsageConsumer; do
  run gcloud projects add-iam-policy-binding "$PROJECT" --member "serviceAccount:$SA" \
    --role "$role" --condition=None --quiet >/dev/null
done
KMS_KEY_NAME="${DLP_KMS_KEY_NAME:-projects/${PROJECT}/locations/us-central1/keyRings/secure-id-extract/cryptoKeys/dlp-wrap}"
KEYRING="$(echo "$KMS_KEY_NAME" | cut -d/ -f6)"
KEY="$(basename "$KMS_KEY_NAME")"
KMS_LOCATION="$(echo "$KMS_KEY_NAME" | cut -d/ -f4)"
# Decrypt on this one key only (DLP unwraps the data key as the caller); viewer for the posture check.
for role in roles/cloudkms.cryptoKeyDecrypter roles/cloudkms.viewer; do
  run gcloud kms keys add-iam-policy-binding "$KEY" --keyring "$KEYRING" --location "$KMS_LOCATION" \
    --project "$PROJECT" --member "serviceAccount:$SA" --role "$role" --quiet >/dev/null
done

echo "== 3/5 Vault key in Secret Manager (${SECRET})"
if ! gcloud secrets describe "$SECRET" --project "$PROJECT" >/dev/null 2>&1; then
  if [[ -n "$DRY" ]]; then
    echo "+ gcloud secrets create $SECRET (random value)" >&2
  else
    python3 -c 'import secrets; print(secrets.token_urlsafe(24), end="")' \
      | gcloud secrets create "$SECRET" --project "$PROJECT" --replication-policy automatic --data-file=-
  fi
fi
run gcloud secrets add-iam-policy-binding "$SECRET" --project "$PROJECT" \
  --member "serviceAccount:$SA" --role roles/secretmanager.secretAccessor --quiet >/dev/null

echo "== 4/5 Build and deploy ${SERVICE} (authenticated only)"
# Explicit either way: gcloud keeps the previous IAP state when neither flag is passed.
if [[ $USE_IAP -eq 1 ]]; then
  IAP_FLAG=(--iap)
else
  IAP_FLAG=(--no-iap)
fi
ENV_VARS="^|^GOOGLE_CLOUD_PROJECT=${PROJECT}|DLP_LOCATION=${DLP_LOCATION:-us-central1}|DLP_KMS_KEY_NAME=${KMS_KEY_NAME}|DLP_WRAPPED_KEY=${DLP_WRAPPED_KEY:-}|MODEL_ARMOR_LOCATION=${MODEL_ARMOR_LOCATION:-us}|MODEL_ARMOR_INPUT_TEMPLATE=${MODEL_ARMOR_INPUT_TEMPLATE:-secure-id-input}|MODEL_ARMOR_OUTPUT_TEMPLATE=${MODEL_ARMOR_OUTPUT_TEMPLATE:-secure-id-output}"
# Optional overrides (shell or .env.local); --set-env-vars replaces the whole env on every deploy.
for var in GEMINI_MODEL GEMINI_LOCATION GEMINI_THINKING_LEVEL RATE_LIMIT_RPM API_KEY; do
  if [[ -n "${!var:-}" ]]; then
    ENV_VARS+="|${var}=${!var}"
  fi
done
run gcloud run deploy "$SERVICE" --source . --project "$PROJECT" --region "$REGION" \
  --service-account "$SA" --no-allow-unauthenticated "${IAP_FLAG[@]}" \
  --max-instances 2 --cpu 1 --memory 1Gi --timeout 120 --concurrency 20 \
  --set-env-vars "$ENV_VARS" \
  --set-secrets "VAULT_API_KEY=${SECRET}:latest" --quiet

echo "== 5/5 Access"
for user in "${USERS[@]}"; do
  if [[ $USE_IAP -eq 1 ]]; then
    run gcloud iap web add-iam-policy-binding --project "$PROJECT" --region "$REGION" \
      --resource-type cloud-run --service "$SERVICE" --member "user:$user" \
      --role roles/iap.httpsResourceAccessor --quiet >/dev/null
  else
    run gcloud run services add-iam-policy-binding "$SERVICE" --project "$PROJECT" --region "$REGION" \
      --member "user:$user" --role roles/run.invoker --quiet >/dev/null
  fi
  echo "Granted access to $user"
done

URL="$(gcloud run services describe "$SERVICE" --project "$PROJECT" --region "$REGION" --format 'value(status.url)' 2>/dev/null || true)"
echo
echo "URL:       ${URL:-<pending>}"
echo "Vault key: gcloud secrets versions access latest --secret ${SECRET} --project ${PROJECT}"
