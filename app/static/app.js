"use strict";

/* CampusGuard AI front end. Everything that comes from an email is escaped before it touches the DOM. */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ESC[c]);
const fmt = (x, digits = 3) => (x === null || x === undefined ? "—" : Number(x).toFixed(digits));

const state = {
  mode: "link",
  config: null,
  samples: [],
  pdfFile: null,
  emlFile: null,
  analystFile: null,
};

async function api(path, options = {}) {
  let res;
  try {
    res = await fetch(path, options);
  } catch {
    const err = new Error("Can't reach the CampusGuard AI server. Is it still running?");
    err.network = true;
    throw err;
  }
  let body = null;
  try { body = await res.json(); } catch { /* empty body */ }
  if (!res.ok) {
    const detail = body && body.detail;
    const message = typeof detail === "string" ? detail : (detail && detail.message) || `Request failed (${res.status}).`;
    const err = new Error(message);
    err.field = detail && detail.field;
    err.status = res.status;
    throw err;
  }
  return body;
}

const postJson = (path, data) =>
  api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });

function uploadFile(file, useLlm = true) {
  const form = new FormData();
  form.append("file", file);
  return api(`/api/v1/analyze/upload?use_llm=${useLlm ? "true" : "false"}`, { method: "POST", body: form });
}

/* ------------------------------------------------------------------ views */

const VIEWS = ["scan", "analyst", "eval"];
const loaded = { analyst: false, eval: false };

function showView(name) {
  if (!VIEWS.includes(name)) name = "scan";
  $$("[data-view-panel]").forEach((p) => { p.hidden = p.dataset.viewPanel !== name; });
  $$(".tab").forEach((t) => t.setAttribute("aria-selected", String(t.dataset.view === name)));
  if (location.hash !== `#${name}`) history.replaceState(null, "", `#${name}`);
  if (name === "analyst" && !loaded.analyst) { loaded.analyst = true; initAnalyst(); }
  if (name === "eval" && !loaded.eval) { loaded.eval = true; loadEval(); }
}

/* ------------------------------------------------------------------ status */

async function loadStatus() {
  try {
    const [health, config] = await Promise.all([api("/api/v1/health"), api("/api/v1/config")]);
    state.config = config;
    const chip = $("#ai-chip");
    chip.classList.remove("on", "warn");
    if (!health.gemini_api_key_configured) {
      chip.textContent = "AI reasoning: off";
      chip.title = "No Gemini API key is configured. Verdicts come from the rule engine.";
    } else if (health.llm_last_status === "FAILED_FALLBACK_USED") {
      chip.textContent = "AI reasoning: error";
      chip.classList.add("warn");
      chip.title = `Last Gemini call failed: ${health.llm_last_error || "unknown error"}`;
    } else {
      chip.textContent = "AI reasoning: on";
      chip.classList.add("on");
      chip.title = `Gemini model: ${health.gemini_model}`;
    }
    const redis = $("#redis-chip");
    redis.textContent = health.redis_backend.includes("live") ? "Trusted list: Redis" : "Trusted list: in-memory";
    redis.title = health.redis_backend;
    if (config.campus_name) $("#brand-sub").textContent = `AI-Powered Email Security for ${config.campus_name} Students`;
    const domain = (config.campus_domains || [])[0];
    if (domain) $("#url-input").placeholder = `e.g. portal.${domain}/login`;
  } catch { /* the page still works without the chips */ }
}

/* ------------------------------------------------------------------ scan form */

function setMode(mode) {
  state.mode = mode;
  $$("[data-mode]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.mode === mode)));
  $$("[data-mode-panel]").forEach((p) => { p.hidden = p.dataset.modePanel !== mode; });
  clearScanErrors();
}

function clearScanErrors() {
  ["url", "pdf", "eml"].forEach((f) => { $(`#${f}-error`).textContent = ""; });
  $("#url-input").removeAttribute("aria-invalid");
  $("#pdf-drop").removeAttribute("aria-invalid");
  $("#eml-text").removeAttribute("aria-invalid");
  $("#scan-status").textContent = "";
}

function showFieldError(field, message) {
  const map = { url: ["#url-error", "#url-input"], pdf: ["#pdf-error", "#pdf-drop"], eml: ["#eml-error", "#eml-text"] };
  const [errSel, inputSel] = map[field] || [];
  if (!errSel) { $("#scan-status").textContent = message; return; }
  $(errSel).textContent = message;
  $(inputSel).setAttribute("aria-invalid", "true");
  if (field === "url") $("#url-input").focus();
}

function setBusy(busy) {
  const btn = $("#scan-btn");
  btn.disabled = busy;
  btn.innerHTML = busy ? '<span class="spinner" aria-hidden="true"></span>Scanning…' : "Scan";
  $("#scan-status").textContent = busy ? "Scanning… this usually takes a few seconds." : "";
}

function setPdfFile(file) {
  state.pdfFile = file || null;
  const example = $("#pdf-example");
  if (!file || ![...example.options].some((o) => o.value === file.name)) example.value = "";  // not an example any more
  $("#pdf-name").textContent = file ? `${file.name} (${Math.max(1, Math.round(file.size / 1024))} KB)` : "or drop it here";
  $("#pdf-error").textContent = "";
  $("#pdf-drop").removeAttribute("aria-invalid");
}

async function submitScan(event) {
  event.preventDefault();
  clearScanErrors();
  const mode = state.mode;

  if (mode === "link" && !$("#url-input").value.trim()) return showFieldError("url", "Paste a link to scan.");
  if (mode === "pdf") {
    if (!state.pdfFile) return showFieldError("pdf", "Choose the PDF you saved from your email.");
    if (state.pdfFile.size > 5 * 1024 * 1024) return showFieldError("pdf", "This PDF is larger than 5 MB.");
  }
  if (mode === "eml" && !state.emlFile && !$("#eml-text").value.trim()) {
    return showFieldError("eml", "Paste the email source or choose an .eml file.");
  }

  setBusy(true);
  try {
    let data;
    if (mode === "link") data = await postJson("/api/v1/scan-url", { url: $("#url-input").value, use_llm: true });
    else if (mode === "pdf") data = await uploadFile(state.pdfFile);
    else if (state.emlFile) data = await uploadFile(state.emlFile);
    else data = await postJson("/api/v1/analyze", { raw_eml: $("#eml-text").value, use_llm: true });
    renderResultInto($("#scan-result"), data);
    loadStatus();
  } catch (err) {
    const field = err.field === "url" ? "url" : err.field === "eml" ? "eml"
      : err.field === "file" ? (mode === "pdf" ? "pdf" : "eml") : null;
    showFieldError(field, err.message);
  } finally {
    setBusy(false);
  }
}

function resetScan() {
  $("#scan-result").innerHTML = "";
  $("#url-input").value = "";
  $("#pdf-input").value = "";
  setPdfFile(null);
  state.emlFile = null;
  $("#eml-file").value = "";
  $("#eml-file-name").textContent = "";
  clearScanErrors();
  window.scrollTo({ top: 0, behavior: "smooth" });
  const focusTarget = { link: "#url-input", pdf: "#pdf-input", eml: "#eml-text" }[state.mode];
  setTimeout(() => $(focusTarget).focus(), 50);
}

/* ------------------------------------------------------------------ result card (same layout for every scan) */

const SOURCE_LABEL = {
  llm: "Quoted by Gemini",
  rules: "Matched by rules",
  sender: "From the sender header",
  url: "From a link or file",
};
const CONFIDENCE_TEXT = {
  HIGH: "All the main checks could run.",
  MEDIUM: "One check couldn't run. It's listed below.",
  LOW: "Several checks couldn't run, so treat this as a first look rather than a final answer.",
};
/* Link scans judge the address only, so their confidence means something different. */
const CONFIDENCE_TEXT_LINK = {
  HIGH: "The address itself gives a clear answer (a trusted-list match or a strong warning sign).",
  MEDIUM: "The address alone can't tell us who runs this site, so treat this as a first look.",
  LOW: "We could check very little about this address.",
};

function aiNote(d) {
  const isUrl = d.input_kind === "url";
  if (d.llm_status === "USED") {
    return `<p class="ai-note used">Checked with AI reasoning (${esc(d.llm_model_used || "Gemini")}).</p>`;
  }
  const tail = isUrl ? "The explanation below is rule-based. The label never depends on AI."
                     : "The result below comes from rule-based checks.";
  return `<p class="ai-note">${esc(d.llm_status_message || "AI reasoning wasn't used.")} ${tail}</p>`;
}

function evidenceList(items) {
  if (!items || !items.length) return '<p class="muted">No specific quotes were needed for this result.</p>';
  return `<ul class="evidence">${items.map((e) => {
    const grounded = e.grounded === true ? '<span class="tag good">found in the email</span>'
      : e.grounded === false ? '<span class="tag badtag">not found in the email</span>' : "";
    return `<li class="${e.grounded === false ? "bad" : ""}"><q>${esc(e.quote)}</q>
      <div class="meta"><span>${esc(e.tactic)}</span>${e.points ? `<span>+${esc(e.points)} pts</span>` : ""}
      <span>${esc(SOURCE_LABEL[e.source] || e.source)}</span>${grounded}</div></li>`;
  }).join("")}</ul>`;
}

/* Wrap verbatim evidence quotes in <mark>, escaping everything else. */
function highlight(text, quotes) {
  const ranges = [];
  for (const q of quotes) {
    const trimmed = (q || "").trim();
    if (trimmed.length < 3) continue;
    const pattern = trimmed.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+");
    const re = new RegExp(pattern, "gi");
    let m;
    while ((m = re.exec(text)) !== null) {
      ranges.push([m.index, m.index + m[0].length]);
      if (m[0].length === 0) re.lastIndex++;
    }
  }
  ranges.sort((a, b) => a[0] - b[0]);
  let out = "";
  let pos = 0;
  for (const [start, end] of ranges) {
    if (end <= pos) continue;
    const s = Math.max(start, pos);
    out += esc(text.slice(pos, s)) + "<mark>" + esc(text.slice(s, end)) + "</mark>";
    pos = end;
  }
  return out + esc(text.slice(pos));
}

function meter(label, value, max) {
  const pct = max ? Math.min(100, Math.round((value / max) * 100)) : 0;
  return `<span>${esc(label)}</span><span class="bar"><span style="width:${pct}%"></span></span><span class="num">${esc(value)}/${esc(max)}</span>`;
}

function detailsBlock(d) {
  const isUrl = d.input_kind === "url";
  const parts = [];
  const confidenceText = (isUrl ? CONFIDENCE_TEXT_LINK : CONFIDENCE_TEXT)[d.confidence] || "";
  parts.push(`<div><h3>Confidence: ${esc((d.confidence || "").toLowerCase())}</h3><p>${esc(confidenceText)}</p></div>`);
  if (d.limitations && d.limitations.length) {
    parts.push(`<div><h3>What we couldn't check</h3><ul class="plain-list">${d.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}</ul></div>`);
  }
  if (isUrl) {
    parts.push(`<div><h3>Risk score: ${esc(d.risk_score)}/100</h3><ul class="plain-list">${(d.reasons || []).map((r) => `<li>${esc(r)}</li>`).join("")}</ul></div>`);
    if (d.llm_status === "USED" && d.explanation) parts.push(`<div><h3>Gemini's explanation</h3><p>${esc(d.explanation)}</p></div>`);
  } else {
    const b = d.score_breakdown;
    parts.push(`<div><h3>Risk score: ${esc(d.risk_score)}/100</h3><div class="meter">
      ${meter("Sender checks", b.sender_integrity_score, 35)}
      ${meter("Links and files", b.url_scan_score, 30)}
      ${meter("Wording and pressure", b.psychological_content_score, 35)}
      ${meter("Known campaign", b.campaign_history_boost, 15)}
    </div>${b.pattern_floor ? `<p class="pattern-note"><strong>Known scam script:</strong> ${esc(b.patterns.join(", "))}. The sender or link couldn't be verified, so the score is at least ${esc(b.pattern_floor)}.</p>` : (b.patterns && b.patterns.length ? `<p class="hint"><strong>Matched script:</strong> ${esc(b.patterns.join(", "))} (sender verified, so no minimum score).</p>` : "")}<p class="hint">The score is the sum of these parts, with minimum scores for known scam scripts, prompt injection and executable attachments.</p></div>`);
    const grounded = d.groundedness === null || d.groundedness === undefined ? ""
      : ` <span class="tag">${Math.round(d.groundedness * 100)}% of Gemini's quotes found in the email</span>`;
    parts.push(`<div><h3>Evidence${grounded}</h3>${evidenceList(d.evidence)}</div>`);
    const email = d.sanitized_email || {};
    const text = `${(email.headers || {}).subject || ""}\n\n${email.body_text || ""}`.trim();
    const quotes = (d.evidence || []).filter((e) => (e.source === "llm" || e.source === "rules") && e.grounded !== false).map((e) => e.quote);
    if (text) parts.push(`<div><h3>Email text</h3><div class="email-text">${highlight(text, quotes)}</div></div>`);
  }
  parts.push(`<div><h3>Technical details</h3><dl class="kv">
    <dt>Engine</dt><dd>${esc(d.engine_used)}</dd>
    <dt>Level / action</dt><dd>${esc(d.risk_level)} / ${esc(d.escalated_action)}</dd>
    <dt>Request</dt><dd class="mono">${esc(d.request_id)}</dd>
    <dt>Time</dt><dd>${esc(d.latency_ms)} ms</dd>
  </dl></div>`);
  return parts.join("");
}

function resultCard(d) {
  const s = d.summary;
  const isUrl = d.input_kind === "url";
  const why = isUrl && d.llm_status === "USED" && d.explanation ? d.explanation : s.why_it_matters;
  const from = !isUrl && d.sanitized_email ? (d.sanitized_email.headers.from_address || "unknown sender") : null;
  const subject = !isUrl && d.sanitized_email ? d.sanitized_email.headers.subject : "";
  const checked = isUrl
    ? `Checked <code>${esc(s.checked)}</code>`
    : `From <code>${esc(from)}</code>${subject ? ` · ${esc(subject)}` : ""}`;

  const actions = (s.actions || []).map((a) => {
    if (a.kind === "open_portal") {
      return `<a class="btn btn-primary" href="${esc(a.url)}" target="_blank" rel="noopener noreferrer">${esc(a.label)}</a>`;
    }
    if (a.kind === "scan_another") return `<button type="button" class="btn btn-secondary" data-act="scan-another">${esc(a.label)}</button>`;
    return "";
  }).join("");

  const paste = s.link_unrecovered ? `
    <form class="paste-link" data-act="paste-link" novalidate>
      <label class="label" for="paste-${esc(d.request_id)}">We couldn't recover the link from this file. Paste it here to check it:</label>
      <div class="row">
        <input class="input" id="paste-${esc(d.request_id)}" type="text" inputmode="url" autocomplete="off" spellcheck="false" placeholder="https://…" />
        <button class="btn btn-primary btn-small" type="submit">Check link</button>
      </div>
      <p class="field-error" role="alert"></p>
      <div class="paste-result"></div>
    </form>` : "";

  return `<article class="card result tone-${esc(s.tone)}">
    <header class="result-head">
      <h2 class="verdict" tabindex="-1"><span class="dot" aria-hidden="true"></span>${esc(s.label)}</h2>
      <span class="checked">${checked}</span>
    </header>
    ${aiNote(d)}
    <dl class="result-body">
      <dt>What we found</dt><dd>${esc(s.finding)}</dd>
      <dt>Why it matters</dt><dd>${esc(why)}</dd>
      <dt>What to do next</dt><dd><ul>${(s.next_steps || []).map((n) => `<li>${esc(n)}</li>`).join("")}</ul></dd>
    </dl>
    ${paste}
    <div class="actions">${actions}</div>
    <details class="more"><summary>How we decided</summary><div class="more-body">${detailsBlock(d)}</div></details>
  </article>`;
}

function renderResultInto(container, data, focus = true) {
  container.innerHTML = resultCard(data);
  if (focus) {
    const heading = $(".verdict", container);
    heading.focus({ preventScroll: true });
    container.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

/* Delegated actions inside result cards */
document.addEventListener("click", (e) => {
  const el = e.target.closest("[data-act]");
  if (!el || el.tagName === "FORM") return;
  if (el.dataset.act === "scan-another") { showView("scan"); resetScan(); }
});

document.addEventListener("submit", async (e) => {
  const form = e.target.closest('form[data-act="paste-link"]');
  if (!form) return;
  e.preventDefault();
  const input = $("input", form);
  const error = $(".field-error", form);
  const out = $(".paste-result", form);
  const button = $("button", form);
  error.textContent = "";
  input.removeAttribute("aria-invalid");
  if (!input.value.trim()) { error.textContent = "Paste the link from the email."; input.setAttribute("aria-invalid", "true"); return; }
  button.disabled = true;
  button.textContent = "Scanning…";
  try {
    const data = await postJson("/api/v1/scan-url", { url: input.value, use_llm: true });
    out.innerHTML = `<div style="margin-top:12px">${resultCard(data)}</div>`;
  } catch (err) {
    error.textContent = err.message;
    input.setAttribute("aria-invalid", "true");
  } finally {
    button.disabled = false;
    button.textContent = "Check link";
  }
});

/* ------------------------------------------------------------------ samples (shared) */

async function loadSamples() {
  if (state.samples.length) return state.samples;
  try {
    const data = await api("/api/v1/samples");
    state.samples = data.samples || [];
  } catch { state.samples = []; }
  return state.samples;
}

async function initScanExamples() {
  const samples = await loadSamples();
  const select = $("#example-select");
  select.innerHTML = '<option value="">Choose a sample email…</option>' +
    samples.map((s, i) => `<option value="${i}">${esc(s.title.replace(/^\d+\.\s*/, ""))}</option>`).join("");
}

/* ------------------------------------------------------------------ analyst view */

const STEP_MAP = {
  INPUT_SANITIZATION: ["INPUT_SANITIZATION", "active"], INPUT_SANITIZED: ["INPUT_SANITIZATION", "done"],
  AGENT_FRAMEWORK: ["AGENT_FRAMEWORK", "done"],
  TOOLS_EXECUTION: ["TOOLS_EXECUTION", "active"], TOOLS_COMPLETED: ["TOOLS_EXECUTION", "done"],
  MEMORY_LOOKUP: ["MEMORY_LOOKUP", "active"], MEMORY_COMPLETED: ["MEMORY_LOOKUP", "done"],
  LLM_REASONING: ["LLM_REASONING", "active"], LLM_FALLBACK: ["LLM_REASONING", "warn"], COMPLETED: ["LLM_REASONING", "done"],
};
const STEP_TEXT = { active: "running…", done: "done", warn: "fallback", waiting: "waiting" };

function resetSteps() {
  $$("#a-steps .step").forEach((li) => {
    li.className = "step";
    $(".s", li).textContent = STEP_TEXT.waiting;
  });
}

function markStep(stage, message) {
  const entry = STEP_MAP[stage];
  if (!entry) return;
  const [id, status] = entry;
  const li = $(`#a-steps .step[data-step="${id}"]`);
  if (!li) return;
  if (stage === "COMPLETED" && li.classList.contains("warn")) return; // keep the fallback visible
  li.className = `step ${status}`;
  $(".s", li).textContent = STEP_TEXT[status];
  if (message && stage !== "COMPLETED") $(".m", li).textContent = message;
}

function markAllDone(fallback) {
  Object.keys(STEP_MAP).forEach((st) => { if (STEP_MAP[st][1] === "done") markStep(st); });
  if (fallback) markStep("LLM_FALLBACK", fallback);
}

async function initAnalyst() {
  const samples = await loadSamples();
  const box = $("#a-samples");
  box.innerHTML = samples.map((s, i) => `
    <button type="button" class="sample" data-sample="${i}" aria-pressed="false">
      <span>${esc(s.title)}</span><span class="cat">${esc(s.category)}</span>
    </button>`).join("");
  if (samples.length) selectAnalystSample(0);
  loadCampaigns();
  loadTrustedDomains();
  loadSkills();
}

function selectAnalystSample(i) {
  const s = state.samples[i];
  if (!s) return;
  $("#a-eml").value = s.raw_eml;
  state.analystFile = null;
  $$("#a-samples .sample").forEach((b) => b.setAttribute("aria-pressed", String(Number(b.dataset.sample) === i)));
}

function analystInputOrError() {
  $("#a-error").textContent = "";
  if (state.analystFile) return { file: state.analystFile };
  const raw = $("#a-eml").value.trim();
  if (!raw) { $("#a-error").textContent = "Paste an email or pick a sample first."; return null; }
  return { raw };
}

function runAnalystWs() {
  const input = analystInputOrError();
  if (!input) return;
  if (input.file) return runAnalystRest(); // PDFs go through the upload endpoint
  resetSteps();
  $("#a-latency").textContent = "streaming…";
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws/analyze`);
  ws.onopen = () => ws.send(JSON.stringify({ raw_eml: input.raw, use_llm: $("#a-use-llm").checked }));
  ws.onerror = () => { $("#a-error").textContent = "The live stream failed. Try HTTPS POST instead."; };
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.stage === "ERROR") { $("#a-error").textContent = msg.message; ws.close(); return; }
    markStep(msg.stage, msg.message);
    if (msg.stage === "COMPLETED") {
      renderAnalyst(msg.data);
      loadCampaigns();
      loadStatus();
      ws.close();
    }
  };
}

async function runAnalystRest() {
  const input = analystInputOrError();
  if (!input) return;
  resetSteps();
  $("#a-latency").textContent = "calling…";
  try {
    const useLlm = $("#a-use-llm").checked;
    const data = input.file ? await uploadFile(input.file, useLlm)
      : await postJson("/api/v1/analyze", { raw_eml: input.raw, use_llm: useLlm });
    markAllDone(data.llm_status !== "USED" ? data.llm_status_message : null);
    renderAnalyst(data);
    loadCampaigns();
    loadStatus();
  } catch (err) {
    $("#a-error").textContent = err.message;
    $("#a-latency").textContent = "error";
  }
}

function authBadge(label, value) {
  const cls = value === "pass" ? "pass" : value === "unavailable" ? "na" : "fail";
  return `<span class="auth ${cls}">${esc(label)}: ${esc(value)}</span>`;
}

function renderAnalyst(d) {
  $("#a-latency").textContent = `${d.latency_ms} ms`;
  $("#a-engine").textContent = d.engine_used;
  const color = d.ui_banner.color || "red";
  $("#a-banner").className = `banner ${color}`;
  $("#a-banner").innerHTML = `
    <div class="row">
      <span class="pill ${esc(color)}">${esc(d.escalated_action)}</span>
      <span class="pill ghost">Score ${esc(d.risk_score)}/100 · ${esc(d.risk_level)}</span>
      <span class="pill ghost">Confidence ${esc(d.confidence)}</span>
      <span class="pill ghost">${esc(d.input_kind)}</span>
      ${d.prompt_injection_detected ? '<span class="pill violet">Prompt injection blocked</span>' : ""}
      <span class="muted mono" style="font-size:0.75rem;margin-left:auto">${esc(d.request_id)}</span>
    </div>
    <h3>${esc(d.ui_banner.headline)}</h3>
    <p>${esc(d.ui_banner.short_analysis)}</p>
    ${d.primary_finding ? `<p><strong>For the student:</strong> ${esc(d.primary_finding)}</p>` : ""}
    <p class="hint"><strong>Next steps:</strong> ${(d.recommended_next_steps || []).map(esc).join(" · ")}</p>`;
  $("#a-llm-note").innerHTML = d.llm_status === "USED"
    ? `<p class="ai-note used" style="margin:10px 0 0">Gemini was used (${esc(d.llm_model_used)}).</p>`
    : `<p class="ai-note" style="margin:10px 0 0"><strong>Fallback:</strong> ${esc(d.llm_status_message)} The verdict was produced by the rule engine.</p>`;

  const b = d.score_breakdown;
  $("#a-tiles").hidden = false;
  $("#t-sender").textContent = `${b.sender_integrity_score}/35`;
  $("#t-url").textContent = `${b.url_scan_score}/30`;
  $("#t-psych").textContent = `${b.psychological_content_score}/35`;
  $("#t-campaign").textContent = `+${b.campaign_history_boost}/15`;
  const pat = $("#t-pattern");
  pat.hidden = !(b.patterns && b.patterns.length);
  pat.textContent = b.pattern_floor ? `Known scam script: ${b.patterns.join(", ")} → final score at least ${b.pattern_floor}.`
    : (b.patterns && b.patterns.length ? `Matched script: ${b.patterns.join(", ")} (sender verified, no minimum score).` : "");

  const si = d.sender_integrity;
  $("#a-trust").textContent = si.in_trusted_domains_redis ? `trusted: ${si.sender_domain}` : `untrusted: ${si.sender_domain || "no sender"}`;
  $("#a-auth").innerHTML = authBadge("SPF", si.spf_status) + authBadge("DKIM", si.dkim_status) + authBadge("DMARC", si.dmarc_status);
  $("#a-sender").innerHTML = (si.findings || []).map((f) => `<li>${esc(f)}</li>`).join("") || '<li class="muted">No findings.</li>';

  const us = d.url_scan;
  $("#a-urlcount").textContent = `${us.total_urls_scanned} URLs, ${us.malicious_count} malicious`;
  $("#a-urls").innerHTML = (us.findings || []).map((f) => `<li>${esc(f)}</li>`).join("") || '<li class="muted">No findings.</li>';

  $("#a-grounded").textContent = d.groundedness === null || d.groundedness === undefined ? ""
    : `${Math.round(d.groundedness * 100)}% of Gemini quotes found verbatim`;
  $("#a-evidence").innerHTML = evidenceList(d.evidence).replace(/^<ul class="evidence">|<\/ul>$/g, "");
  const text = `${d.sanitized_email.headers.subject || ""}\n\n${d.sanitized_email.body_text || ""}`.trim();
  const quotes = (d.evidence || []).filter((e) => (e.source === "llm" || e.source === "rules") && e.grounded !== false).map((e) => e.quote);
  $("#a-email-text").innerHTML = highlight(text, quotes);

  const notes = [
    ...(d.psychological_tactics || []),
    ...((d.sanitized_email.sanitization_notes || []).map((n) => `[Sanitizer] ${n}`)),
  ];
  $("#a-psych").innerHTML = notes.map((n) => `<li>${esc(n)}</li>`).join("") || '<li class="muted">None.</li>';
  $("#a-limits").innerHTML = (d.limitations || []).length
    ? `<div class="callout warn"><strong>What couldn't be checked</strong><ul class="plain-list">${d.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}</ul></div>`
    : "";
}

async function loadCampaigns() {
  try {
    const data = await api("/api/v1/campaigns");
    $("#a-campaigns").innerHTML = (data.campaigns || []).map((c) => `
      <tr><td class="mono">${esc(c.campaign_id)}</td><td class="mono">${esc(c.sender_domain)}</td>
      <td>${esc(c.subject_pattern)}</td><td class="num">${esc(c.seen_count)}</td>
      <td class="num">${esc(c.last_risk_score)}</td><td><span class="tag">${esc(c.last_action)}</span></td></tr>`).join("")
      || '<tr><td colspan="6" class="muted">No campaigns yet.</td></tr>';
  } catch { /* ignore */ }
}

async function loadTrustedDomains() {
  try {
    const data = await api("/api/v1/trusted-domains");
    $("#domain-list").innerHTML = Object.entries(data.domains || {}).sort().map(([domain, cat]) => `
      <div class="domain-row"><span><code>${esc(domain)}</code> <span class="muted">${esc(cat)}</span></span>
      <button class="btn-link" data-remove-domain="${esc(domain)}">Remove</button></div>`).join("");
  } catch { /* ignore */ }
}

async function loadSkills() {
  try {
    const data = await api("/api/v1/skills");
    $("#skills-content").textContent =
      `=== base_system_prompt.md ===\n${data.base_system_prompt}\n\n` +
      `=== skills/content-analysis.md ===\n${data.content_analysis_skill}\n\n` +
      `=== skills/scam-scoring.md ===\n${data.scam_scoring_skill}`;
  } catch { $("#skills-content").textContent = "Couldn't load the playbooks."; }
}

/* ------------------------------------------------------------------ evaluation view */

// Runs dataset items through the live app and counts right and wrong from that run.
const USED_KEY = "scamshield.eval.used";
const KIND_LABEL = { eml: "Email file", pdf: "Email PDF", url: "Link", plain_text: "Pasted text" };
const DIFFICULTY_ORDER = ["easy", "medium", "hard"];
const evalRun = { items: [], threshold: 60, used: new Set(), order: [], results: new Map(), running: false, stop: false };

function loadUsedIds() {
  try { return new Set(JSON.parse(sessionStorage.getItem(USED_KEY) || "[]")); } catch { return new Set(); }
}

function saveUsedIds() {
  try { sessionStorage.setItem(USED_KEY, JSON.stringify([...evalRun.used])); } catch { /* kept in memory only */ }
}

function shuffle(list) {
  const a = list.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

// Half phishing, half legit; if one side runs short, the other fills the gap.
function balancedPick(pool, n) {
  const phish = shuffle(pool.filter((i) => i.label === "phishing"));
  const legit = shuffle(pool.filter((i) => i.label === "legit"));
  const half = Math.ceil(n / 2);
  let picked = phish.slice(0, half).concat(legit.slice(0, n - half));
  if (picked.length < n) {
    picked = picked.concat(shuffle(phish.slice(half).concat(legit.slice(n - half))).slice(0, n - picked.length));
  }
  return picked;
}

// Random runs never repeat an item in this browser session until every item has been used.
function chooseRunItems(choice) {
  const all = evalRun.items;
  if (choice === "all") return { list: shuffle(all), note: "" };
  const n = Math.min(Number(choice), all.length);
  const fresh = all.filter((i) => !evalRun.used.has(i.id));
  let picked;
  let note = "";
  if (fresh.length >= n) {
    picked = balancedPick(fresh, n);
  } else {
    evalRun.used = new Set(fresh.map((i) => i.id));
    const extra = balancedPick(all.filter((i) => !evalRun.used.has(i.id)), n - fresh.length);
    picked = fresh.concat(extra);
    note = fresh.length
      ? `Only ${fresh.length} unused items were left, so ${extra.length} items from earlier runs were used again.`
      : "Every item had already been used in this session, so a new round started.";
  }
  picked.forEach((i) => evalRun.used.add(i.id));
  saveUsedIds();
  return { list: shuffle(picked), note };
}

function updateSizeNote() {
  const choice = $("#e-size").value;
  const total = evalRun.items.length;
  const added = evalRun.items.filter((i) => i.source === "added").length;
  const unused = evalRun.items.filter((i) => !evalRun.used.has(i.id)).length;
  const inDataset = `The dataset has ${total} items${added ? `, ${added} of them added by you` : ""}.`;
  let text;
  if (choice === "all") {
    text = `Runs every item. ${inDataset}`;
  } else if (Number(choice) >= total) {
    text = `${inDataset} That is fewer than ${choice}, so this runs every item.`;
  } else {
    text = `Picks ${choice} random items, half phishing and half legit. ${inDataset} `
      + `Items don't repeat in this browser session until all have been used (${unused} unused left).`;
  }
  if ($("#e-live-llm").checked) {
    text += " With Gemini on, every item is one Gemini call, so big runs are slow and can hit the free-tier limit.";
  }
  $("#e-size-note").textContent = text;
}

async function loadEval() {
  evalRun.used = loadUsedIds();
  await loadItems();
}

async function loadItems() {
  try {
    const data = await api("/api/v1/eval/items");
    evalRun.items = data.items || [];
    evalRun.threshold = data.threshold;
    $("#e-live").disabled = evalRun.running;
    $("#e-threshold").textContent = `phishing = score ≥ ${evalRun.threshold}`;
  } catch (err) {
    evalRun.items = [];
    $("#e-live").disabled = true;
    $("#e-size-note").textContent = err.message;
    renderAddedList();
    return;
  }
  const added = evalRun.items.filter((i) => i.source === "added").length;
  $("#e-warning").textContent = added
    ? `Mostly synthetic data, plus ${added} item${added === 1 ? "" : "s"} you added. These numbers describe this dataset, not real-world accuracy.`
    : "Synthetic data: these numbers describe this dataset, not real-world accuracy.";
  updateSizeNote();
  renderAddedList();
}

function renderAddedList() {
  const added = evalRun.items.filter((i) => i.source === "added");
  $("#e-added-count").textContent = added.length ? `(${added.length} added)` : "";
  $("#e-added-wrap").hidden = !added.length;
  $("#e-added-rows").innerHTML = added.map((i) => `<tr><td class="mono">${esc(i.id)}</td>
    <td>${esc(KIND_LABEL[i.input_kind] || i.input_kind)}</td><td>${esc(i.label)}</td><td>${esc(i.title || "")}</td>
    <td><button class="btn-link" type="button" data-remove-item="${esc(i.id)}">Remove</button></td></tr>`).join("");
}

async function submitAddItems(event) {
  event.preventDefault();
  const label = ($('input[name="e-add-label"]:checked') || {}).value || "";
  const files = $("#e-add-files").files;
  const links = $("#e-add-links").value;
  const error = $("#e-add-error");
  error.textContent = "";
  $("#e-add-result").innerHTML = "";
  if (!label) { error.textContent = "Choose whether these items are phishing or legit."; return; }
  if (!files.length && !links.trim()) { error.textContent = "Choose at least one file or paste at least one link."; return; }

  const form = new FormData();
  form.append("label", label);
  form.append("links", links);
  for (const f of files) form.append("files", f);
  const button = $("#e-add-btn");
  button.disabled = true;
  button.textContent = "Adding…";
  try {
    const r = await api("/api/v1/eval/items", { method: "POST", body: form });
    const parts = [`<p class="status-line">Added ${r.added.length} item${r.added.length === 1 ? "" : "s"} as ${esc(label)}.</p>`];
    if (r.rejected.length) {
      parts.push(`<p class="field-error">${r.rejected.length} not added:</p><ul class="reject-list">`
        + r.rejected.map((x) => `<li><strong>${esc(x.name)}</strong>: ${esc(x.reason)}</li>`).join("") + "</ul>");
    }
    $("#e-add-result").innerHTML = parts.join("");
    if (r.added.length) {
      $("#e-add-files").value = "";
      $("#e-add-links").value = "";
    }
    await loadItems();
  } catch (err) {
    error.textContent = err.message;
  } finally {
    button.disabled = false;
    button.textContent = "Add to dataset";
  }
}

// Removing deletes the stored file, so it takes a second click to confirm.
async function removeAddedItem(button) {
  if (button.dataset.armed !== "1") {
    button.dataset.armed = "1";
    button.textContent = "Click again to remove";
    setTimeout(() => { if (button.isConnected) { button.dataset.armed = ""; button.textContent = "Remove"; } }, 4000);
    return;
  }
  button.disabled = true;
  try {
    await api(`/api/v1/eval/items/${encodeURIComponent(button.dataset.removeItem)}`, { method: "DELETE" });
    evalRun.used.delete(button.dataset.removeItem);
    saveUsedIds();
    await loadItems();
  } catch (err) {
    $("#e-add-error").textContent = err.message;
    button.disabled = false;
  }
}

function runCounts(results) {
  const c = { tp: 0, fp: 0, tn: 0, fn: 0, errors: 0, gemini: 0, fallback: 0 };
  for (const r of results) {
    if (r.error) { c.errors++; continue; }
    const real = r.label === "phishing";
    const said = r.predicted === "phishing";
    if (real && said) c.tp++;
    else if (real) c.fn++;
    else if (said) c.fp++;
    else c.tn++;
    if (r.llm_status === "USED") c.gemini++;
    else if (r.llm_status === "FAILED_FALLBACK_USED") c.fallback++;
  }
  return c;
}

// Same definitions as eval/metrics.py: undefined values stay empty instead of pretending to be 0.
function metricsOf(c) {
  const ratio = (a, b) => (b ? a / b : null);
  const precision = ratio(c.tp, c.tp + c.fp);
  const recall = ratio(c.tp, c.tp + c.fn);
  let f1 = null;
  if (precision !== null && recall !== null) f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { precision, recall, f1, accuracy: ratio(c.tp + c.tn, c.tp + c.tn + c.fp + c.fn) };
}

function metricRows(c, m) {
  const n = c.tp + c.fp + c.tn + c.fn;
  const flagged = c.tp + c.fp;
  const scams = c.tp + c.fn;
  const rows = [
    ["Accuracy", m.accuracy, `Right on ${c.tp + c.tn} of ${n} items.`],
    ["Precision", m.precision, flagged
      ? `Of the ${flagged} items it called phishing, ${c.tp} really were. 1.00 means no false alarms.`
      : "It hasn't called anything phishing yet."],
    ["Recall", m.recall, scams
      ? `Of the ${scams} real scams, it caught ${c.tp}. 1.00 means no scam got through.`
      : "No real scams in this run yet."],
    ["F1", m.f1, "Precision and recall combined into one number. It is only high when both are."],
  ];
  return rows.map(([name, v, text]) => `<dt>${esc(name)} <b>${fmt(v, 2)}</b></dt><dd>${esc(text)}</dd>`).join("");
}

function groupRows(results) {
  const meta = new Map(evalRun.items.map((i) => [i.id, i]));
  const hasAdded = results.some((r) => (meta.get(r.id) || {}).source === "added");
  const groups = new Map();
  for (const r of results) {
    const it = meta.get(r.id);
    if (r.error || !it) continue;
    const keys = [`Input: ${KIND_LABEL[it.input_kind] || it.input_kind}`, `Difficulty: ${it.difficulty}`];
    if (hasAdded) keys.push(it.source === "added" ? "Source: added by you" : "Source: generated");
    for (const key of keys) {
      const g = groups.get(key) || { n: 0, right: 0, wrong: 0, missed: 0, falseAlarm: 0 };
      g.n++;
      if (r.correct) {
        g.right++;
      } else {
        g.wrong++;
        if (r.label === "phishing") g.missed++;
        else g.falseAlarm++;
      }
      groups.set(key, g);
    }
  }
  const rank = (k) => {
    if (k.startsWith("Input")) return [0, k];
    if (k.startsWith("Source")) return [2, k];
    const pos = DIFFICULTY_ORDER.indexOf(k.split(": ")[1]);
    return [1, String(pos === -1 ? 9 : pos)];  // "unrated" (added items) after easy, medium, hard
  };
  const keys = [...groups.keys()].sort((a, b) => {
    const [ra, sa] = rank(a);
    const [rb, sb] = rank(b);
    return ra - rb || sa.localeCompare(sb);
  });
  return keys.map((k) => {
    const g = groups.get(k);
    return `<tr><td>${esc(k)}</td><td class="num">${g.n}</td><td class="num">${g.right}</td><td class="num">${g.wrong}</td>
      <td class="num">${g.missed}</td><td class="num">${g.falseAlarm}</td></tr>`;
  }).join("") || '<tr><td colspan="6" class="muted">Nothing finished yet.</td></tr>';
}

function renderRunStats() {
  const results = evalRun.order.map((i) => evalRun.results.get(i.id)).filter(Boolean);
  const c = runCounts(results);
  const m = metricsOf(c);
  const n = c.tp + c.fp + c.tn + c.fn;
  $("#e-cm-title").textContent = `${n} item${n === 1 ? "" : "s"} · score ≥ ${evalRun.threshold}`;
  $("#e-confusion").innerHTML = `
    <span></span><span class="h">App said phishing</span><span class="h">App said legit</span>
    <span class="rh">Really phishing</span>
    <div class="cell right"><b>${c.tp}</b>caught</div><div class="cell wrong"><b>${c.fn}</b>missed</div>
    <span class="rh">Really legit</span>
    <div class="cell wrong"><b>${c.fp}</b>false alarm</div><div class="cell right"><b>${c.tn}</b>correctly allowed</div>`;
  const notes = [`${c.tp + c.tn} right, ${c.fp + c.fn} wrong.`];
  if (c.errors) notes.push(`${c.errors} item(s) couldn't be run and aren't counted.`);
  if (n) {
    notes.push(c.gemini || c.fallback
      ? `Gemini answered ${c.gemini} item(s); ${c.fallback} fell back to the rules.`
      : "Every answer came from the rule engine (no Gemini).");
  }
  if (n && n < 30) notes.push("With fewer than 30 items these numbers jump around a lot from run to run.");
  $("#e-cm-note").textContent = notes.join(" ");
  $("#e-metrics").innerHTML = metricRows(c, m);
  $("#e-groups").innerHTML = groupRows(results);
}

function runRow(it) {
  return `<tr data-live="${esc(it.id)}" data-wrong="0"><td class="mono">${esc(it.id)}</td>
    <td>${esc(KIND_LABEL[it.input_kind] || it.input_kind)}</td><td>${esc(it.attack_type)}</td><td>${esc(it.label)}</td>
    <td class="pred">…</td><td class="num score"></td><td class="res muted">waiting</td></tr>`;
}

function fillRow(row, r) {
  row.classList.add("clickable");
  if (r.error) {
    row.dataset.wrong = "1";
    $(".res", row).innerHTML = '<span class="bad-text">couldn&#39;t run</span>';
    return;
  }
  row.dataset.wrong = r.correct ? "0" : "1";
  $(".pred", row).textContent = r.predicted;
  $(".score", row).textContent = r.risk_score;
  $(".res", row).innerHTML = r.correct ? '<span class="ok-text">right</span>' : '<span class="bad-text">wrong</span>';
}

function showRunItem(id) {
  const r = evalRun.results.get(id);
  const box = $("#e-live-result");
  if (!r) return;
  if (r.error) {
    box.innerHTML = `<p class="field-error"><span class="mono">${esc(id)}</span>: ${esc(r.error)}</p>`;
    return;
  }
  box.innerHTML = `<p class="hint" style="margin-top:14px"><span class="mono">${esc(id)}</span> · Truth: <strong>${esc(r.label)}</strong>
    · App said: <strong>${esc(r.predicted)}</strong> (score ${esc(r.risk_score)}, phishing at ${esc(r.threshold)} or more)
    · ${r.correct ? '<span class="ok-text">right</span>' : '<span class="bad-text">wrong</span>'}</p>${resultCard(r.result)}`;
  box.scrollIntoView({ block: "nearest" });
}

function setRunControls(running) {
  $("#e-live").disabled = running;
  $("#e-live").textContent = running ? "Running…" : "Run";
  $("#e-stop").hidden = !running;
  $("#e-stop").disabled = false;
  $("#e-size").disabled = running;
  $("#e-live-llm").disabled = running;
}

async function runPool(list, limit, task) {
  let next = 0;
  const worker = async () => {
    while (!evalRun.stop && next < list.length) await task(list[next++]);
  };
  await Promise.all(Array.from({ length: Math.min(limit, list.length) }, worker));
}

async function runEval() {
  if (evalRun.running || !evalRun.items.length) return;
  const useLlm = $("#e-live-llm").checked;
  const { list, note } = chooseRunItems($("#e-size").value);
  Object.assign(evalRun, { running: true, stop: false, order: list, results: new Map() });
  setRunControls(true);
  $("#e-results").hidden = false;
  $("#e-live-result").innerHTML = "";
  $("#e-only-wrong").checked = false;
  $("#e-live-rows").classList.remove("only-wrong");
  $("#e-live-rows").innerHTML = list.map(runRow).join("");
  renderRunStats();

  let done = 0;
  const suffix = note ? ` ${note}` : "";
  const progress = () => { $("#e-progress").textContent = `${done} of ${list.length} items done.${suffix}`; };
  progress();
  const started = performance.now();
  // Gemini calls go one at a time (rate limits); rule-only runs use a few parallel requests.
  await runPool(list, useLlm ? 1 : 4, async (it) => {
    const row = $(`tr[data-live="${CSS.escape(it.id)}"]`);
    $(".res", row).textContent = "running…";
    let r;
    try {
      r = await api(`/api/v1/eval/run-item/${encodeURIComponent(it.id)}?use_llm=${useLlm}`, { method: "POST" });
    } catch (err) {
      r = { id: it.id, label: it.label, error: err.message, correct: null };
    }
    evalRun.results.set(it.id, r);
    fillRow(row, r);
    done++;
    progress();
    renderRunStats();
  });

  const secs = ((performance.now() - started) / 1000).toFixed(1);
  $$("#e-live-rows .res").forEach((td) => { if (td.textContent === "waiting") td.textContent = "not run"; });
  $("#e-progress").textContent = evalRun.stop
    ? `Stopped after ${done} of ${list.length} items (${secs} s).${suffix}`
    : `Finished ${done} items in ${secs} s.${suffix}`;
  evalRun.running = false;
  setRunControls(false);
  updateSizeNote();
}

/* ------------------------------------------------------------------ wiring */

function wire() {
  $$(".tab").forEach((t) => t.addEventListener("click", () => showView(t.dataset.view)));
  $$("[data-view-link]").forEach((a) => a.addEventListener("click", (e) => { e.preventDefault(); showView(a.dataset.viewLink); }));
  window.addEventListener("hashchange", () => showView(location.hash.slice(1)));

  $$("[data-mode]").forEach((b) => b.addEventListener("click", () => setMode(b.dataset.mode)));
  $("#scan-form").addEventListener("submit", submitScan);
  $("#url-input").addEventListener("input", () => { $("#url-error").textContent = ""; $("#url-input").removeAttribute("aria-invalid"); });

  $("#pdf-input").addEventListener("change", (e) => setPdfFile(e.target.files[0]));
  const drop = $("#pdf-drop");
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("dragging"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, () => drop.classList.remove("dragging")));
  drop.addEventListener("drop", (e) => { e.preventDefault(); if (e.dataTransfer.files[0]) setPdfFile(e.dataTransfer.files[0]); });

  const setEmlFile = (f) => {
    state.emlFile = f || null;
    $("#eml-file-name").textContent = f ? ` ${f.name} selected` : "";
    $("#eml-error").textContent = "";
  };
  $("#eml-file").addEventListener("change", (e) => setEmlFile(e.target.files[0]));
  // "Drop your .eml file here": a file dropped on the text box is used like a chosen file; dropped text is pasted as usual.
  $("#eml-text").addEventListener("dragover", (e) => { if (e.dataTransfer.types.includes("Files")) e.preventDefault(); });
  $("#eml-text").addEventListener("drop", (e) => {
    const f = e.dataTransfer.files[0];
    if (!f) return;
    e.preventDefault();
    $("#eml-file").value = "";
    setEmlFile(f);
  });
  $("#eml-text").addEventListener("input", () => {
    if (state.emlFile) { state.emlFile = null; $("#eml-file").value = ""; $("#eml-file-name").textContent = ""; }
  });
  $("#link-examples").addEventListener("click", (e) => {
    const chip = e.target.closest("[data-example-url]");
    if (!chip) return;
    $("#url-input").value = chip.dataset.exampleUrl;
    clearScanErrors();
  });
  $("#pdf-example").addEventListener("change", async (e) => {
    const name = e.target.value;
    if (!name) return;
    try {
      const res = await fetch(`/static/samples/${encodeURIComponent(name)}`);
      if (!res.ok) throw new Error("not found");
      setPdfFile(new File([await res.blob()], name, { type: "application/pdf" }));
    } catch {
      showFieldError("pdf", "Couldn't load that example. Is the server still running?");
    }
  });
  $("#example-select").addEventListener("change", (e) => {
    const s = state.samples[Number(e.target.value)];
    if (e.target.value !== "" && s) {
      $("#eml-text").value = s.raw_eml;
      state.emlFile = null;
      $("#eml-file-name").textContent = "";
    }
  });

  // analyst
  $("#a-samples").addEventListener("click", (e) => { const b = e.target.closest("[data-sample]"); if (b) selectAnalystSample(Number(b.dataset.sample)); });
  $("#a-ws").addEventListener("click", runAnalystWs);
  $("#a-rest").addEventListener("click", runAnalystRest);
  $("#a-refresh").addEventListener("click", loadCampaigns);
  $("#a-eml").addEventListener("input", () => { state.analystFile = null; });
  $("#a-file").addEventListener("change", (e) => {
    const f = e.target.files[0];
    if (!f) return;
    $$("#a-samples .sample").forEach((b) => b.setAttribute("aria-pressed", "false"));
    if (f.name.toLowerCase().endsWith(".pdf")) {
      state.analystFile = f;
      $("#a-eml").value = `[PDF selected: ${f.name}. It will be analysed with HTTPS POST.]`;
    } else {
      state.analystFile = null;
      const reader = new FileReader();
      reader.onload = () => { $("#a-eml").value = reader.result; };
      reader.readAsText(f);
    }
    e.target.value = "";
  });

  // modals
  $$("[data-open-modal]").forEach((b) => b.addEventListener("click", () => { $(`#${b.dataset.openModal}`).hidden = false; }));
  $$("[data-close-modal]").forEach((b) => b.addEventListener("click", () => { b.closest(".modal").hidden = true; }));
  $$(".modal").forEach((m) => m.addEventListener("click", (e) => { if (e.target === m) m.hidden = true; }));
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") $$(".modal").forEach((m) => { m.hidden = true; }); });
  $("#domain-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const domain = $("#domain-new").value.trim();
    if (!domain) return;
    await postJson("/api/v1/trusted-domains", { domain, category: $("#domain-cat").value.trim() || "Verified domain" });
    $("#domain-new").value = "";
    loadTrustedDomains();
  });
  $("#domain-list").addEventListener("click", async (e) => {
    const b = e.target.closest("[data-remove-domain]");
    if (!b) return;
    await api(`/api/v1/trusted-domains/${encodeURIComponent(b.dataset.removeDomain)}`, { method: "DELETE" });
    loadTrustedDomains();
  });

  // evaluation
  $("#e-live").addEventListener("click", runEval);
  $("#e-stop").addEventListener("click", () => { evalRun.stop = true; $("#e-stop").disabled = true; });
  $("#e-size").addEventListener("change", updateSizeNote);
  $("#e-live-llm").addEventListener("change", updateSizeNote);
  $("#e-only-wrong").addEventListener("change", (e) => $("#e-live-rows").classList.toggle("only-wrong", e.target.checked));
  $("#e-live-rows").addEventListener("click", (e) => {
    const row = e.target.closest("tr.clickable[data-live]");
    if (row) showRunItem(row.dataset.live);
  });
  $("#e-add-form").addEventListener("submit", submitAddItems);
  $("#e-added-rows").addEventListener("click", (e) => {
    const button = e.target.closest("[data-remove-item]");
    if (button) removeAddedItem(button);
  });
}

wire();
loadStatus();
initScanExamples();
showView(location.hash.slice(1) || "scan");
