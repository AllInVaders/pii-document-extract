// Secure ID Extract front end. All server strings are rendered with textContent (no innerHTML).

const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...children) => {
  const node = Object.assign(document.createElement(tag), props);
  for (const child of children.flat()) {
    if (child == null) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
};

const STAGE_LABELS = {
  image_guard: "Upload hygiene",
  model_armor_input: "Model Armor: input",
  gemini_extract: "Gemini extraction",
  instruction_check: "Embedded instructions",
  document_check: "Document check",
  validators: "Deterministic checks",
  redaction: "Redacted preview",
  dlp_kms_tokenize: "DLP + KMS tokens",
  leak_guard: "Leak guard",
  model_armor_output: "Model Armor: output",
};
const PLANNED = ["image_guard", "model_armor_input", "gemini_extract", "validators",
  "redaction", "dlp_kms_tokenize", "leak_guard", "model_armor_output"];
const FIELD_LABELS = {
  document_number: "Document number", surnames: "Surnames", given_names: "Given names",
  date_of_birth: "Date of birth", card_number: "Card number", sex: "Sex", nationality: "Nationality",
  marital_status: "Marital status", issue_date: "Issue date", expiry_date: "Expiry date",
  check_digit: "Check digit", document_type: "Type", issuing_country: "Issuing country",
};
const CLAIM_LABELS = {
  document_number_checksum_valid: "Check digit valid", is_adult: "Adult (18+)",
  is_expired: "Expired", dates_consistent: "Dates consistent", age_band: "Age band", checked_on: "Checked on",
};

let currentFile = null;
let lastResult = null;
let vaultTimer = null;

// ---------- Tabs ----------
document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((t) => { t.classList.toggle("active", t === tab); t.setAttribute("aria-selected", t === tab); });
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${tab.dataset.view}`));
  if (tab.dataset.view === "posture") loadPosture();
  if (tab.dataset.view === "audit") loadAudit();
}));

document.querySelectorAll(".seg-btn").forEach((btn) => btn.addEventListener("click", () => {
  document.querySelectorAll(".seg-btn").forEach((b) => b.classList.toggle("active", b === btn));
  document.querySelectorAll(".role-panel").forEach((p) => p.classList.toggle("active", p.id === `panel-${btn.dataset.role}`));
}));

// ---------- Input ----------
const drop = $("drop");
$("file-input").addEventListener("change", (e) => e.target.files[0] && setFile(e.target.files[0]));
["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", (e) => e.dataTransfer.files[0] && setFile(e.dataTransfer.files[0]));

function setFile(file, sampleName = null) {
  currentFile = file;
  const img = $("original-img");
  if (img.src.startsWith("blob:")) URL.revokeObjectURL(img.src);
  img.src = URL.createObjectURL(file);
  img.classList.add("blurred");
  $("toggle-original").textContent = "Show";
  $("toggle-original").setAttribute("aria-pressed", "false");
  $("original-card").hidden = false;
  $("run-btn").disabled = false;
  document.querySelectorAll(".chip").forEach((c) => c.classList.toggle("selected", c.dataset.name === sampleName));
}

$("toggle-original").addEventListener("click", (e) => {
  const blurred = $("original-img").classList.toggle("blurred");
  e.target.textContent = blurred ? "Show" : "Hide";
  e.target.setAttribute("aria-pressed", String(!blurred));
});

async function loadSamples() {
  try {
    const { samples } = await (await fetch("/api/samples")).json();
    const labels = { "synthetic_pe_dni.png": "Synthetic DNI", "synthetic_pe_dni_injection.png": "DNI with prompt injection" };
    $("samples").replaceChildren(...samples.map((s) => {
      const chip = el("button", { className: "chip", type: "button", textContent: labels[s.name] || s.name });
      chip.dataset.name = s.name;
      chip.addEventListener("click", async () => {
        const blob = await (await fetch(s.url)).blob();
        setFile(new File([blob], s.name, { type: blob.type }), s.name);
      });
      return chip;
    }));
  } catch { /* samples are optional */ }
}

// ---------- Run ----------
$("run-btn").addEventListener("click", run);

async function run() {
  if (!currentFile) return;
  $("run-btn").disabled = true;
  $("consumer-card").hidden = true;
  $("banner").hidden = true;
  $("total-ms").textContent = "";
  clearVault();
  renderStages(PLANNED.map((name, i) => ({ name, status: i === 0 ? "running" : "pending" })));

  // Cosmetic progress while the request is in flight; replaced by real stages on response.
  let step = 0;
  const ticker = setInterval(() => {
    step = Math.min(step + 1, 2);
    renderStages(PLANNED.map((name, i) => ({ name, status: i < step ? "pass" : i === step ? "running" : "pending" })));
  }, 1600);

  const form = new FormData();
  form.append("file", currentFile);
  let body = null;
  let status = 0;
  try {
    const resp = await fetch("/api/extract", { method: "POST", body: form });
    status = resp.status;
    body = await resp.json();
  } catch {
    body = { blocked: true, reason: "Network error", stages: [] };
  } finally {
    clearInterval(ticker);
    $("run-btn").disabled = false;
  }

  renderStages(body.stages || []);
  if (body.blocked || status >= 400) {
    showBanner("bad", body.reason || body.detail || `Request failed (${status})`);
    lastResult = null;
    return;
  }
  lastResult = body;
  $("total-ms").textContent = `${body.total_ms} ms`;
  const review = body.agent_view.needs_human_review;
  showBanner(review ? "warn" : "ok", review
    ? `Extracted with review flags: ${body.agent_view.low_confidence_fields.join(", ") || "check digit or legibility"}.`
    : "Extracted. All PII tokenized before leaving the service.");
  renderAgent(body.agent_view);
  renderBanker(body.banker_view, body.redacted_preview);
  $("consumer-card").hidden = false;
}

function renderStages(stages) {
  const items = stages.map((s) => el("li", { className: `stage ${s.status}`, title: s.reason || "" },
    el("span", { className: "dot" }),
    el("span", { className: "stage-name", textContent: STAGE_LABELS[s.name] || s.name }),
    el("span", { className: "stage-ms", textContent: s.ms != null && s.status !== "pending" && s.status !== "running" ? `${s.ms} ms` : "" })));
  $("stages").replaceChildren(...items);
}

function showBanner(kind, text) {
  const b = $("banner");
  b.className = `banner ${kind}`;
  b.textContent = text;
  b.hidden = false;
}

function pill(value) {
  if (value === true) return el("span", { className: "pill ok", textContent: "Yes" });
  if (value === false) return el("span", { className: "pill bad", textContent: "No" });
  if (value == null) return el("span", { className: "pill na", textContent: "n/a" });
  return document.createTextNode(String(value));
}

function kv(target, entries, render = (v) => document.createTextNode(v || "—")) {
  $(target).replaceChildren(...entries.flatMap(([k, v]) => [
    el("dt", { textContent: FIELD_LABELS[k] || CLAIM_LABELS[k] || k }),
    el("dd", {}, render(v, k)),
  ]));
}

function renderAgent(view) {
  const claims = Object.entries(view.kyc_claims).filter(([k]) => k !== "checked_on");
  kv("claims", claims, (v, k) => {
    if (k !== "is_expired" || v == null) return pill(v);
    // For "expired", Yes is the bad outcome.
    return el("span", { className: `pill ${v ? "bad" : "ok"}`, textContent: v ? "Yes" : "No" });
  });
  kv("agent-doc", [["document_type", view.document_type], ["issuing_country", view.issuing_country],
    ["nationality", view.nationality], ["expiry_date", view.expiry_date]]);
  kv("tokens", Object.entries(view.tokens));
  $("agent-json").textContent = JSON.stringify(view, null, 2);
}

function renderBanker(view, preview) {
  kv("masked", Object.entries(view.masked));
  kv("attributes", Object.entries(view.attributes));
  const img = $("redacted-img");
  if (preview.data_url) {
    img.src = preview.data_url;
    img.hidden = false;
    $("redacted-note").textContent = `${preview.redacted_boxes} regions blacked out using boxes returned by Gemini.`;
  } else {
    img.removeAttribute("src");
    img.hidden = true;
    $("redacted-note").textContent = `Preview withheld: no box for ${preview.missing.join(", ")}. Showing nothing is safer than a partial mask.`;
  }
}

// ---------- Vault ----------
$("vault-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!lastResult) { $("vault-note").textContent = "Run an extraction first."; return; }
  clearVault();
  const resp = await fetch("/api/vault/reidentify", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Vault-Key": $("vault-key").value },
    body: JSON.stringify({ tokens: lastResult.agent_view.tokens }),
  });
  const body = await resp.json();
  if (!resp.ok) { $("vault-note").textContent = body.detail || `Denied (${resp.status})`; return; }
  kv("vault-values", Object.entries(body.values));
  let left = 30;
  $("vault-note").textContent = `Re-identified through Cloud DLP in ${body.ms} ms. Clearing in ${left}s.`;
  vaultTimer = setInterval(() => {
    left -= 1;
    if (left <= 0) { clearVault(); $("vault-note").textContent = "Cleared."; return; }
    $("vault-note").textContent = `Re-identified through Cloud DLP in ${body.ms} ms. Clearing in ${left}s.`;
  }, 1000);
});

function clearVault() {
  if (vaultTimer) clearInterval(vaultTimer);
  vaultTimer = null;
  $("vault-values").replaceChildren();
  $("vault-note").textContent = "";
}

// ---------- Posture ----------
$("refresh-posture").addEventListener("click", loadPosture);
async function loadPosture() {
  $("checks").replaceChildren(el("li", { className: "check" }, el("span", { className: "muted", textContent: "Checking…" })));
  try {
    const { checks } = await (await fetch("/api/posture")).json();
    $("checks").replaceChildren(...checks.map((c) => el("li", { className: "check" },
      el("span", { className: `pill ${c.status === "ok" ? "ok" : c.status === "fail" ? "bad" : "na"}`, textContent: c.status.toUpperCase() }),
      el("span", { className: "name", textContent: c.label }),
      el("span", { className: "detail", textContent: c.detail }))));
  } catch {
    $("checks").replaceChildren(el("li", { className: "check", textContent: "Could not load posture." }));
  }
}

// ---------- Audit ----------
$("refresh-audit").addEventListener("click", loadAudit);
async function loadAudit() {
  const { events } = await (await fetch("/api/audit")).json();
  if (!events.length) {
    $("audit-rows").replaceChildren(el("tr", {}, el("td", { colSpan: 6, className: "muted", textContent: "No events yet." })));
    return;
  }
  $("audit-rows").replaceChildren(...events.map((e) => el("tr", {},
    el("td", { className: "mono", textContent: (e.at || "").replace("T", " ").replace("+00:00", "") }),
    el("td", { className: "mono", textContent: e.request_id }),
    el("td", {}, el("span", { className: `pill ${e.outcome === "ok" || e.outcome === "reidentified" ? "ok" : "bad"}`, textContent: e.outcome })),
    el("td", { className: "hash", textContent: e.image_sha256 ? `${e.image_sha256.slice(0, 16)}…` : "—" }),
    el("td", { className: "small", textContent: (e.stages || []).map((s) => `${STAGE_LABELS[s.name] || s.name}: ${s.status}`).join(" · ") || (e.fields || []).join(", ") }),
    el("td", { className: "num", textContent: e.total_ms ?? "" }))));
}

// ---------- Boot ----------
fetch("/health").then((r) => r.json()).then((h) => { $("model-chip").textContent = h.model; }).catch(() => {});
loadSamples();
