// ShipSafe dashboard. All report values are inserted with textContent (never innerHTML):
// reports contain strings taken from uploaded projects.
"use strict";

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const COMPONENT_NAMES = {
  platformio_intelligence: "PlatformIO intelligence",
  hardware_intelligence: "Hardware intelligence",
  security_engine: "Security engine",
};
const $ = (id) => document.getElementById(id);
const state = { report: null, severities: new Set(SEVERITIES), component: "" };

function el(tag, text, attrs = {}) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
  return node;
}

function setText(id, text) { $(id).textContent = text ?? ""; }

// ------------------------------------------------------------------ startup
async function init() {
  try {
    const health = await (await fetch("/api/health")).json();
    const node = $("health");
    node.textContent = health.status === "ok"
      ? `backend ok · ${health.clang.version} · ${health.rules.security} security rules`
      : `backend degraded: ${health.error || health.clang.error || "see /api/health"}`;
    node.className = "health " + (health.status === "ok" ? "ok" : "bad");
  } catch {
    $("health").textContent = "backend unreachable";
    $("health").className = "health bad";
  }
  try {
    const { profiles } = await (await fetch("/api/profiles")).json();
    // Only verified profiles are selectable. Planned targets live in the static roadmap
    // section so nobody can pick one and mistake skipped checks for real findings.
    for (const p of profiles.filter((p) => p.supported)) {
      $("chip").append(el("option", p.name, { value: p.id }));
    }
  } catch { /* chip list stays at auto-detect */ }

  const severityChips = $("sev-filter");
  for (const sev of SEVERITIES) {
    const chip = el("button", sev, { type: "button", "data-sev": sev, "aria-pressed": "true" });
    chip.addEventListener("click", () => {
      state.severities.has(sev) ? state.severities.delete(sev) : state.severities.add(sev);
      chip.setAttribute("aria-pressed", state.severities.has(sev) ? "true" : "false");
      renderUnified();
    });
    severityChips.append(chip);
  }
  $("comp-filter").addEventListener("change", (e) => { state.component = e.target.value; renderUnified(); });

  const file = $("file");
  const dropzone = $("dropzone");
  file.addEventListener("change", () => onFileChosen(file.files[0]));
  dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("drag"); });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag"));
  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("drag");
    if (e.dataTransfer.files.length) {
      file.files = e.dataTransfer.files;
      onFileChosen(e.dataTransfer.files[0]);
    }
  });
  $("scan-form").addEventListener("submit", (e) => { e.preventDefault(); startScan(false); });
  $("demo-btn").addEventListener("click", () => startScan(true));
  $("download-btn").addEventListener("click", downloadReport);
  for (const tab of document.querySelectorAll(".tabs button")) {
    tab.addEventListener("click", () => showTab(tab.dataset.tab));
  }
}

function onFileChosen(file) {
  const ok = file && file.name.toLowerCase().endsWith(".zip");
  $("scan-btn").disabled = !ok;
  $("file-label").textContent = ok ? `Selected: ${file.name} (${(file.size / 1024).toFixed(0)} KB)` : "Please choose a .zip file";
}

// ------------------------------------------------------------------ scanning
async function startScan(demo) {
  showError("");
  const body = new FormData();
  body.append("chip", $("chip").value);
  body.append("registry", $("registry").value);
  if (!demo) body.append("file", $("file").files[0]);
  setBusy(true);
  try {
    const response = await fetch(demo ? "/api/scan/demo" : "/api/scan", { method: "POST", body });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || `HTTP ${response.status}`);
    await poll(data.scan_id);
  } catch (error) {
    showError(error.message);
  } finally {
    setBusy(false);
  }
}

async function poll(scanId) {
  $("progress-card").hidden = false;
  $("results").hidden = true;
  for (;;) {
    const scan = await (await fetch(`/api/scan/${encodeURIComponent(scanId)}`)).json();
    renderStepper(scan.stages || [], scan.stage, scan.status);
    if (scan.status === "completed") { render(scan); return; }
    if (scan.status === "failed") throw new Error(scan.error || "scan failed");
    await new Promise((r) => setTimeout(r, 600));
  }
}

function renderStepper(stages, current, status) {
  const list = $("stepper");
  list.replaceChildren();
  const index = stages.indexOf(current);
  stages.forEach((stage, i) => {
    const done = status === "completed" || i < index;
    list.append(el("li", stage, { class: done ? "done" : i === index ? "active" : "" }));
  });
  setText("progress-text", status === "completed" ? "Scan finished." : `Running: ${current}…`);
}

function setBusy(busy) {
  $("scan-btn").disabled = busy || !($("file").files[0]);
  $("demo-btn").disabled = busy;
}

function showError(message) {
  $("form-error").hidden = !message;
  $("form-error").textContent = message;
}

// ------------------------------------------------------------------ rendering
function render(report) {
  state.report = report;
  $("results").hidden = false;
  $("demo-banner").hidden = !report.demo;
  const risk = report.risk_assessment;
  const summary = report.summary;

  setText("score", risk.score);
  const priority = $("priority");
  priority.textContent = risk.review_priority;
  priority.dataset.sev = risk.review_priority;
  setText("t-deps", summary.dependencies_scanned);
  setText("t-deps-sub", `${summary.package_findings} finding(s)`);
  setText("t-hw", summary.hardware_findings);
  const hw = report.hardware_analysis;
  setText("t-hw-sub", hw.status === "skipped" ? "validation unavailable for target" : `profile ${hw.profile ? hw.profile.module : "?"}`);
  setText("t-sec", summary.security_findings);
  setText("t-sec-sub", `${summary.files_parsed} file(s) parsed`);
  setText("t-cov", risk.completeness);
  $("t-cov").dataset.sev = risk.completeness === "COMPLETE" ? "LOW" : "MEDIUM";
  setText("t-cov-sub", `${report.errors.length} issue(s)`);

  setText("statement", risk.statement);
  const reasons = $("incomplete");
  reasons.replaceChildren(...risk.incomplete_reasons.map((r) => el("li", r)));
  const rows = risk.contributions.map((c) => {
    const tr = el("tr");
    tr.append(el("td", c.rule_id, { class: "mono" }), el("td", COMPONENT_NAMES[c.component]));
    const sev = el("td"); sev.append(el("span", c.severity, { class: "pill", "data-sev": c.severity }));
    tr.append(sev, el("td", `${c.findings}${c.counted < c.findings ? ` (${c.counted} counted)` : ""}`),
      el("td", c.points), el("td", c.formula, { class: "mono" }));
    return tr;
  });
  $("contrib-table").querySelector("tbody").replaceChildren(...rows);
  $("contrib-table").hidden = rows.length === 0;
  $("no-contrib").hidden = rows.length !== 0;
  setText("disclaimer", report.disclaimer);

  renderUnified();
  renderDependencies(report);
  renderHardware(report);
  renderSecurity(report);
  renderIssues(report);
  showTab("report");
  $("results").scrollIntoView({ behavior: "smooth", block: "start" });
}

function findingCard(f) {
  const node = $("finding-tpl").content.firstElementChild.cloneNode(true);
  const sev = node.querySelector(".sev");
  sev.textContent = f.severity;
  sev.dataset.sev = f.severity;
  node.querySelector(".rule").textContent = f.rule_id;
  node.querySelector(".cat").textContent = f.category.replaceAll("_", " ").toLowerCase();
  node.querySelector(".comp").textContent = "· " + COMPONENT_NAMES[f.component];
  node.querySelector(".conf").textContent = `confidence: ${f.confidence.toLowerCase()}`;
  node.querySelector(".desc").textContent = f.description;
  const where = f.file ? `${f.file}${f.line ? ":" + f.line : ""}` : "project";
  node.querySelector(".loc").textContent = `${where}${f.origin && f.origin !== "project" ? "  ·  " + f.origin : ""}`;
  node.querySelector(".evidence").textContent = f.evidence || "(no evidence text)";
  node.querySelector(".expl").textContent = f.explanation;
  node.querySelector(".rec").textContent = "Recommendation: " + f.recommendation;
  return node;
}

function fillFindings(containerId, findings, emptyText) {
  const container = $(containerId);
  container.replaceChildren(...(findings.length ? findings.map(findingCard) : [el("p", emptyText, { class: "empty" })]));
}

function renderUnified() {
  if (!state.report) return;
  const list = state.report.findings.filter((f) =>
    state.severities.has(f.severity) && (!state.component || f.component === state.component));
  fillFindings("report-list", list, "No findings match the selected filters.");
}

function renderDependencies(report) {
  const rows = report.package_results.map((r) => {
    const tr = el("tr");
    const name = el("td");
    name.append(el("strong", r.package));
    if (r.dependency.declared === false) name.append(el("span", "installed, not declared (transitive)", { class: "sub" }));
    const meta = r.metadata;
    if (meta && meta.description) name.append(el("span", meta.description, { class: "sub" }));
    const kind = el("td", r.kind.replaceAll("_", " "));
    const version = el("td", r.dependency.version_spec || r.dependency.git_ref || "—", { class: "mono" });
    const status = el("td", r.metadata_status.replaceAll("_", " "));
    if (meta) {
      status.append(el("span", `owner ${meta.owner ?? "?"} · latest ${meta.latest_version ?? "?"}`, { class: "sub" }));
      if (meta.repository_url) status.append(el("span", meta.repository_url, { class: "sub" }));
      status.append(el("span", `retrieved ${meta.retrieved_at}${meta.from_cache ? " (cache)" : ""}`, { class: "sub" }));
    } else if (r.metadata_error) {
      status.append(el("span", r.metadata_error, { class: "sub" }));
    }
    const identity = el("td", r.trust_status.replaceAll("_", " "));
    if (r.similarity) {
      identity.append(el("span", `≈ ${r.similarity.matched_trusted_package} (${r.similarity.relation}, ${r.similarity.similarity_score})`, { class: "sub" }));
    }
    const count = el("td");
    for (const f of r.findings) count.append(el("span", `${f.rule_id} `, { class: "pill", "data-sev": f.severity }));
    if (!r.findings.length) count.textContent = "—";
    tr.append(name, kind, version, status, identity, count);
    return tr;
  });
  $("dep-table").querySelector("tbody").replaceChildren(...rows);
  fillFindings("dep-findings", report.findings.filter((f) => f.component === "platformio_intelligence"),
    "No dependency findings.");
}

function metaItem(label, value) {
  const div = el("div");
  div.append(el("span", label), document.createTextNode(value ?? "—"));
  return div;
}

function renderHardware(report) {
  const hw = report.hardware_analysis;
  const selection = hw.selection || {};
  const unavailable = hw.status === "skipped";
  $("hw-unavailable").hidden = !unavailable;
  setText("hw-unavailable-detail", unavailable ? (selection.error || "No verified hardware profile matches this project.") : "");
  $("t-hw").closest(".tile").classList.toggle("unavailable", unavailable);
  $("hw-meta").replaceChildren(
    metaItem("Status", hw.status.replaceAll("_", " ")),
    metaItem("Profile", hw.profile ? `${hw.profile.display_name}` : "none"),
    metaItem("Selected by", selection.resolved_by || selection.error || "—"),
    metaItem("GPIO operations", `${hw.operations_checked} checked, ${hw.unresolved_operations} unresolved`),
    metaItem("Board(s)", (hw.boards || []).map((b) => `${b.board} (${b.mcu || "unknown MCU"})`).join(", ")),
  );
  const rows = (hw.pin_usage || []).map((p) => {
    const tr = el("tr");
    const caps = p.capabilities
      ? Object.entries(p.capabilities).filter(([, v]) => v).map(([k, v]) => (v === true ? k : `${k} ${v}`)).join(", ")
      : "not a GPIO of this chip";
    tr.append(el("td", `GPIO${p.gpio}`, { class: "mono" }), el("td", p.requirements.join(", ")),
      el("td", caps || "general purpose"), el("td", p.locations.join("  "), { class: "mono" }));
    return tr;
  });
  $("pin-table").querySelector("tbody").replaceChildren(...rows);
  $("pin-table").hidden = rows.length === 0;
  fillFindings("hw-findings", report.hardware_results,
    unavailable ? "Hardware validation was not run for this target — see Scan issues." : "No hardware findings.");
}

function renderSecurity(report) {
  const sec = report.security_analysis || {};
  const byCategory = Object.entries(sec.by_category || {}).map(([k, v]) => `${k.replaceAll("_", " ").toLowerCase()}: ${v}`);
  $("sec-meta").replaceChildren(
    metaItem("Findings by category", byCategory.join(" · ") || "none"),
    metaItem("Unresolved calls", sec.unresolved_calls ?? 0),
    metaItem("Indirect calls (not followed)", sec.indirect_calls ?? 0),
  );
  fillFindings("sec-findings", report.security_results, "No security pattern findings.");
}

function renderIssues(report) {
  setText("issue-count", report.errors.length);
  const items = report.errors.map((e) => {
    const div = el("div", null, { class: `issue ${e.level}` });
    div.append(el("strong", `${e.stage} · ${e.level.toLowerCase()}: `), document.createTextNode(e.message));
    if (e.file) div.append(el("small", `${e.file}${e.line ? ":" + e.line : ""}`));
    return div;
  });
  $("issue-list").replaceChildren(...(items.length ? items : [el("p", "No issues: every stage completed.", { class: "empty" })]));
  const ast = report.analysis.ast || {};
  const rows = (ast.files || []).map((f) => {
    const tr = el("tr");
    tr.append(el("td", f.file, { class: "mono" }), el("td", f.status.replaceAll("_", " ")), el("td", f.error_count),
      el("td", f.stubbed_headers.join(", ") || "—", { class: "mono" }));
    return tr;
  });
  $("file-table").querySelector("tbody").replaceChildren(...rows);
  const ctx = ast.compile_context;
  setText("context-note", ctx ? `Compilation context: ${ctx.mode}. ${ctx.notes.join(" ")}` : "");
}

function showTab(name) {
  for (const tab of document.querySelectorAll(".tabs button")) tab.classList.toggle("active", tab.dataset.tab === name);
  for (const panel of document.querySelectorAll(".tab-panel")) panel.hidden = panel.dataset.panel !== name;
}

function downloadReport() {
  if (!state.report) return;
  const blob = new Blob([JSON.stringify(state.report, null, 2)], { type: "application/json" });
  const link = el("a", null, { href: URL.createObjectURL(blob), download: `shipsafe-${state.report.scan_id}.json` });
  document.body.append(link);
  link.click();
  link.remove();
}

init();
