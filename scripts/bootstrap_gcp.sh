#!/usr/bin/env bash
# Idempotent GCP bootstrap for secure-id-extract.
#   - enables the APIs
#   - creates a Cloud KMS key and a KMS-wrapped AES-256 key for Cloud DLP
#   - creates the two Model Armor templates (input and output) in the `us` multi-region
#   - writes non-secret resource names plus the *wrapped* key to .env.local (gitignored)
set -euo pipefail
cd "$(dirname "$0")/.."

PROJECT="${GOOGLE_CLOUD_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
if [[ -z "${PROJECT}" ]]; then
  echo "Set GOOGLE_CLOUD_PROJECT or run: gcloud config set project <PROJECT_ID>" >&2
  exit 1
fi
KMS_LOCATION="${KMS_LOCATION:-us-central1}"
KEYRING="${KMS_KEYRING:-secure-id-extract}"
KEY="${KMS_KEY:-dlp-wrap}"
MA_LOCATION="${MODEL_ARMOR_LOCATION:-us}"
MA_INPUT="${MODEL_ARMOR_INPUT_TEMPLATE:-secure-id-input}"
MA_OUTPUT="${MODEL_ARMOR_OUTPUT_TEMPLATE:-secure-id-output}"
ENV_FILE=".env.local"

echo "Project: ${PROJECT}"
gcloud services enable aiplatform.googleapis.com modelarmor.googleapis.com \
  dlp.googleapis.com cloudkms.googleapis.com --project="${PROJECT}"

# --- Cloud KMS ---------------------------------------------------------------
gcloud kms keyrings describe "${KEYRING}" --location="${KMS_LOCATION}" --project="${PROJECT}" >/dev/null 2>&1 \
  || gcloud kms keyrings create "${KEYRING}" --location="${KMS_LOCATION}" --project="${PROJECT}"
gcloud kms keys describe "${KEY}" --keyring="${KEYRING}" --location="${KMS_LOCATION}" --project="${PROJECT}" >/dev/null 2>&1 \
  || gcloud kms keys create "${KEY}" --keyring="${KEYRING}" --location="${KMS_LOCATION}" \
       --purpose=encryption --rotation-period=90d \
       --next-rotation-time="$(date -u -d '+90 days' +%Y-%m-%dT%H:%M:%SZ)" --project="${PROJECT}"
KMS_KEY_NAME="projects/${PROJECT}/locations/${KMS_LOCATION}/keyRings/${KEYRING}/cryptoKeys/${KEY}"

EXISTING_WRAPPED=""
if [[ -f "${ENV_FILE}" ]] && grep -q "^GOOGLE_CLOUD_PROJECT=${PROJECT}$" "${ENV_FILE}"; then
  # Only reuse a wrapped key that belongs to this project's KMS key.
  EXISTING_WRAPPED="$(grep -E '^DLP_WRAPPED_KEY=' "${ENV_FILE}" | cut -d= -f2- || true)"
fi
if [[ -n "${EXISTING_WRAPPED}" ]]; then
  WRAPPED_KEY="${EXISTING_WRAPPED}"
  echo "Reusing existing wrapped DLP key (tokens stay stable)."
else
  # The plaintext AES key only exists in this pipe; only the KMS ciphertext is kept.
  WRAPPED_KEY="$(head -c 32 /dev/urandom | gcloud kms encrypt --key="${KEY}" --keyring="${KEYRING}" \
      --location="${KMS_LOCATION}" --project="${PROJECT}" \
      --plaintext-file=- --ciphertext-file=- | base64 -w0)"
  echo "Created new KMS-wrapped DLP key."
fi

# --- Model Armor templates (us multi-region supports image screening) ---------
MA_BASE="https://modelarmor.${MA_LOCATION}.rep.googleapis.com/v1/projects/${PROJECT}/locations/${MA_LOCATION}/templates"
TOKEN="$(gcloud auth print-access-token)"

create_template() {
  local id="$1" body="$2"
  local code
  code="$(curl -s -o /tmp/ma_get.json -w '%{http_code}' -H "Authorization: Bearer ${TOKEN}" "${MA_BASE}/${id}")"
  if [[ "${code}" == "200" ]]; then
    echo "Model Armor template exists: ${id}"
    return
  fi
  curl -sf -X POST -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" \
    -d "${body}" "${MA_BASE}?templateId=${id}" >/dev/null
  echo "Created Model Armor template: ${id}"
}

# Input: an ID card always contains PII, so SDP is not used here (it would always match).
# The gate is about attacks: prompt injection printed on the card, malicious URLs, RAI, CSAM.
create_template "${MA_INPUT}" '{
  "filterConfig": {
    "raiSettings": {"raiFilters": [
      {"filterType": "HATE_SPEECH", "confidenceLevel": "HIGH"},
      {"filterType": "HARASSMENT", "confidenceLevel": "HIGH"},
      {"filterType": "DANGEROUS", "confidenceLevel": "HIGH"},
      {"filterType": "SEXUALLY_EXPLICIT", "confidenceLevel": "HIGH"}]},
    "piAndJailbreakFilterSettings": {"filterEnforcement": "ENABLED", "confidenceLevel": "MEDIUM_AND_ABOVE"},
    "maliciousUriFilterSettings": {"filterEnforcement": "ENABLED"},
    "csamFilterSettings": {"filterEnforcement": "ENABLED"}
  },
  "templateMetadata": {
    "multiLanguageDetection": {"enableMultiLanguageDetection": true},
    "modalities": ["MODALITY_IMAGE", "MODALITY_TEXT"]
  }
}'

# Output: screens the tokenized payload before it leaves the service.
create_template "${MA_OUTPUT}" '{
  "filterConfig": {
    "piAndJailbreakFilterSettings": {"filterEnforcement": "ENABLED", "confidenceLevel": "MEDIUM_AND_ABOVE"},
    "maliciousUriFilterSettings": {"filterEnforcement": "ENABLED"},
    "sdpSettings": {"basicConfig": {"filterEnforcement": "ENABLED"}}
  },
  "templateMetadata": {"multiLanguageDetection": {"enableMultiLanguageDetection": true}}
}'

cat > "${ENV_FILE}" <<EOF
GOOGLE_CLOUD_PROJECT=${PROJECT}
DLP_LOCATION=${KMS_LOCATION}
DLP_KMS_KEY_NAME=${KMS_KEY_NAME}
DLP_WRAPPED_KEY=${WRAPPED_KEY}
MODEL_ARMOR_LOCATION=${MA_LOCATION}
MODEL_ARMOR_INPUT_TEMPLATE=${MA_INPUT}
MODEL_ARMOR_OUTPUT_TEMPLATE=${MA_OUTPUT}
EOF
chmod 600 "${ENV_FILE}"
echo "Wrote ${ENV_FILE}"
