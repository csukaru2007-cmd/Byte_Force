"use strict";
const API = (window.SHIPSAFE_API_BASE || "").replace(/\/$/, "");
const $ = (id) => document.getElementById(id);
const TEXT = { GREEN: "READY TO UPLOAD", YELLOW: "REVIEW REQUIRED", RED: "UPLOAD BLOCKED" };
let file = null;

function el(tag, text, cls) { const e = document.createElement(tag); if (text != null) e.textContent = text; if (cls) e.className = cls; return e; }
function fill(list, items) { list.replaceChildren(...items.map((t) => el("li", t))); }
function pill(node, status) { node.textContent = status || "UNAVAILABLE"; node.className = "pill " + (status || "NONE"); }

async function health() {
  try {
    const h = await (await fetch(API + "/api/health")).json();
    const ml = h.ml && h.ml.available ? "ML model loaded" : "ML model UNAVAILABLE";
    const bl = h.baseline && h.baseline.configured ? "baseline configured" : "baseline not configured";
    $("health").textContent = `Backend ${h.status} · ${ml} · ${bl}`;
  } catch (e) { $("health").textContent = "Backend unreachable at " + (API || "this origin"); }
}

function setFile(f) {
  file = f && f.name.toLowerCase().endsWith(".zip") ? f : null;
  $("file-label").innerHTML = file ? `<strong>${file.name.replace(/</g, "&lt;")}</strong> selected` : "<strong>Choose a .zip</strong> of a PlatformIO project, or drop it here";
  $("scan-btn").disabled = !file;
}
$("file").addEventListener("change", (e) => setFile(e.target.files[0]));
const dz = $("dropzone");
dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("over"); });
dz.addEventListener("dragleave", () => dz.classList.remove("over"));
dz.addEventListener("drop", (e) => { e.preventDefault(); dz.classList.remove("over"); setFile(e.dataTransfer.files[0]); });

$("scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!file) return;
  $("form-error").hidden = true; $("results").hidden = true; $("scan-btn").disabled = true;
  const body = new FormData(); body.append("file", file);
  try {
    const r = await fetch(API + "/api/scan", { method: "POST", body });
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || r.statusText);
    await poll(data.scan_id);
  } catch (err) { $("form-error").textContent = "Scan failed: " + err.message; $("form-error").hidden = false; }
  finally { $("scan-btn").disabled = !file; }
});

async function poll(id) {
  $("progress").hidden = false;
  for (;;) {
    const rep = await (await fetch(`${API}/api/scan/${id}`)).json();
    const i = Math.max(0, rep.stages.indexOf(rep.stage));
    $("bar-fill").style.width = `${Math.round(((i + 1) / rep.stages.length) * 100)}%`;
    $("progress-text").textContent = `Stage: ${rep.stage} (${rep.status})`;
    if (rep.status === "completed" || rep.status === "failed") { $("progress").hidden = true; return render(id, rep); }
    await new Promise((res) => setTimeout(res, 700));
  }
}

async function render(id, rep) {
  const d = rep.decision || { status: "YELLOW", reasons: ["No decision returned."] };
  $("verdict").className = "verdict " + d.status;
  $("verdict-text").textContent = TEXT[d.status];
  fill($("verdict-reasons"), (d.reasons || []).slice(0, 4).concat(rep.error ? ["Error: " + rep.error] : []));
  try {   // ask the backend gate: the page never decides by itself
    const g = await fetch(`${API}/api/scan/${id}/upload`, { method: "POST" });
    $("gate").textContent = `Backend upload gate: HTTP ${g.status} — ${g.ok ? "upload permitted" : "upload refused"}`;
  } catch (e) { $("gate").textContent = "Backend upload gate unreachable — upload refused."; }

  const main = rep.main_engine_decision || {};
  pill($("main-status"), main.status);
  const sev = (rep.risk_assessment || {}).findings_by_severity || {};
  $("main-counts").textContent = Object.entries(sev).filter(([, n]) => n).map(([s, n]) => `${n} ${s}`).join(" · ") || "No findings";
  fill($("main-reasons"), main.reasons || []);

  const ml = rep.ml_prediction || {};
  pill($("ml-status"), ml.status === "ok" ? ml.label : null);
  $("ml-probs").replaceChildren(...Object.entries(ml.probabilities || {}).map(([k, v]) => {
    const row = el("div", null, "prob"); row.append(el("span", k), el("span", (v * 100).toFixed(1) + "%"));
    const b = el("div", null, "pbar " + k); b.style.width = v * 100 + "%"; row.append(b); return row;
  }));
  const val = ml.validation;
  $("ml-note").textContent = ml.status === "ok"
    ? `Random Forest on 100 synthetic projects. Grouped-CV accuracy ${val ? val.accuracy : "?"}, macro F1 ${val ? val.macro_f1 : "?"}. Advisory signal only.`
    : "ML unavailable: " + (ml.reason || "no prediction") + ". GREEN is impossible without it.";

  const findings = rep.findings || [];
  const box = $("findings");
  box.replaceChildren(...(findings.length ? findings.slice(0, 25).map((f) => {
    const row = el("div", null, "finding");
    row.append(el("span", f.severity, "sev " + f.severity), el("code", f.rule_id),
      el("span", f.description), el("span", `${f.file || ""}${f.line ? ":" + f.line : ""}`, "muted small"));
    return row;
  }) : [el("p", rep.status === "failed" ? "Analysis failed — no findings available." : "No findings.", "muted")]));
  if (findings.length > 25) box.append(el("p", `+ ${findings.length - 25} more in the JSON report (GET /api/scan/${id}).`, "muted small"));

  pill($("cmp-ss"), main.status);
  fill($("cmp-ss-list"), findings.filter((f) => f.severity !== "INFO").slice(0, 8).map((f) => `${f.severity} ${f.rule_id}: ${f.description}`));
  const bl = rep.baseline || { status: "unavailable" };
  $("cmp-bl-title").textContent = "Baseline (LLM-only, our own service)";
  pill($("cmp-bl"), bl.risk_class);
  fill($("cmp-bl-list"), (bl.findings || []).slice(0, 8).map((f) => `${f.severity} ${f.rule_id || ""}: ${f.title}${f.line ? " (line " + f.line + ")" : ""}`));
  $("cmp-bl-note").textContent = bl.risk_class
    ? `${bl.label}. Model: ${bl.model || "?"}. ${bl.risk_class_rule}. Not used in the upload decision.`
    : `Baseline UNAVAILABLE: ${bl.reason || bl.status}. No baseline result is shown.`;
  $("results").hidden = false;
}

health();
