"use strict";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const FINDINGS_VIEW = "__findings__";

const STATUS_LABEL = {
  ok:          "ok",
  error:       "error",
  unsupported: "flag not supported by this tool version",
  no_tool:     "tool not installed",
  skipped:     "skipped",
};

const FALLBACK_LABELS = {
  critical: "Tier 1", high: "Tier 2", medium: "Tier 3", low: "Tier 3", info: "Context",
};

const state = { report: null, view: FINDINGS_VIEW, query: "" };
const $ = (sel) => document.querySelector(sel);

function sevLabel(key) {
  return (state.report && state.report.severity_labels && state.report.severity_labels[key])
      || FALLBACK_LABELS[key] || key;
}

// ------------------------------------------------------------------ //
//  Theme                                                               //
// ------------------------------------------------------------------ //

function initTheme() {
  let t = null;
  try { t = localStorage.getItem("adexec-theme"); } catch (e) {}
  if (!t) t = matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", t);
}
$("#themeToggle").addEventListener("click", () => {
  const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", next);
  try { localStorage.setItem("adexec-theme", next); } catch (e) {}
});
initTheme();

// ------------------------------------------------------------------ //
//  Boot + load                                                         //
// ------------------------------------------------------------------ //

async function boot() {
  let targets = [];
  try { targets = await (await fetch("/api/targets")).json(); } catch (e) {}

  if (!targets.length) {
    $("#empty").hidden = false;
    document.querySelector("main").style.display = "none";
    $("#summary").style.display = "none";
    return;
  }

  const sel = $("#targetSelect");
  sel.innerHTML = "";
  targets.forEach((t) => {
    const o = document.createElement("option");
    o.value = t.report;
    o.textContent = t.target + (t.domain ? `  (${t.domain})` : "");
    sel.appendChild(o);
  });
  sel.addEventListener("change", () => loadReport(sel.value));

  const wanted = new URLSearchParams(location.search).get("target");
  const match = targets.find((t) => t.target === wanted);
  sel.value = (match || targets[0]).report;
  await loadReport(sel.value);
}

async function loadReport(url) {
  state.report = await (await fetch(url)).json();
  state.view = FINDINGS_VIEW;
  state.query = "";
  $("#search").value = "";
  $("#searchCount").textContent = "";
  renderMeta(); renderSummary(); renderSidebar(); renderDetail();
}

// ------------------------------------------------------------------ //
//  Header + summary                                                    //
// ------------------------------------------------------------------ //

function renderMeta() {
  const r = state.report;
  const bits = [];
  if (r.hostname) bits.push(`<b>${esc(r.hostname)}</b>`);
  if (r.domain)   bits.push(esc(r.domain));
  bits.push(esc(r.target));
  if (r.creds)    bits.push(`creds: ${esc(r.creds)}`);
  if (r.finished_at) bits.push(esc(r.finished_at.replace("T", " ")));
  $("#meta").innerHTML = bits.join(" &nbsp;·&nbsp; ");
}

function renderSummary() {
  const r = state.report, sc = r.severity_counts || {}, st = r.status_counts || {};
  const chips = [];
  SEV_ORDER.forEach((s) => {
    if (sc[s]) chips.push(`<span class="chip sev-${s}"><span class="dot"></span><b>${sc[s]}</b> ${esc(sevLabel(s))}</span>`);
  });
  // neutral, clearly-separate run facts
  chips.push(`<span class="chip ghost"><b>${(r.open_ports||[]).length}</b> ports</span>`);
  chips.push(`<span class="chip ghost"><b>${(r.users||[]).length}</b> users</span>`);
  chips.push(`<span class="chip ghost"><b>${(r.shares||[]).length}</b> shares</span>`);
  if (st.no_tool) chips.push(`<span class="chip ghost" title="Commands skipped because the tool isn't installed"><b>${st.no_tool}</b> tools missing</span>`);
  $("#summary").innerHTML = chips.join("");
}

// ------------------------------------------------------------------ //
//  Sidebar                                                             //
// ------------------------------------------------------------------ //

function maxSeverity(step) {
  for (const s of SEV_ORDER) if ((step.findings||[]).some((f) => f.severity === s)) return s;
  return null;
}

function stepMatchCount(step) {
  if (!state.query) return 0;
  const q = state.query.toLowerCase(), hay = (step.raw_output || "").toLowerCase();
  let n = 0, i = hay.indexOf(q);
  while (i !== -1) { n++; i = hay.indexOf(q, i + q.length); }
  return n;
}

function stepMatches(step) {
  if (!state.query) return true;
  return (step.name + " " + step.category + " " + step.command + " " +
          step.raw_output + " " + (step.findings||[]).map((f) => f.text).join(" "))
         .toLowerCase().includes(state.query.toLowerCase());
}

function renderSidebar() {
  const r = state.report, nav = $("#sidebar");
  nav.innerHTML = "";

  const total = (r.findings || []).length;
  nav.appendChild(navItem({
    label: "Findings", id: FINDINGS_VIEW,
    right: `<span class="count ${total ? "sev-" + (SEV_ORDER.find((s)=> (r.severity_counts||{})[s]) || "info") : "none"}">${total}</span>`,
    active: state.view === FINDINGS_VIEW,
  }));

  const byCat = {};
  (r.results || []).forEach((s) => { if (stepMatches(s)) (byCat[s.category] ||= []).push(s); });

  (r.categories || []).forEach((cat) => {
    const steps = byCat[cat];
    if (!steps || !steps.length) return;
    const h = document.createElement("div");
    h.className = "nav-cat"; h.textContent = cat;
    nav.appendChild(h);
    steps.forEach((s) => {
      const mc = stepMatchCount(s);
      const sev = maxSeverity(s);
      let right = "";
      if (mc) right = `<span class="count match-badge">${mc}</span>`;
      else if (s.findings && s.findings.length)
        right = `<span class="count sev-${sev}">${s.findings.length}</span>`;
      nav.appendChild(navItem({ label: s.name, id: s.id, status: s.status, right,
        active: state.view === s.id }));
    });
  });
}

function navItem({ label, id, status, right = "", active }) {
  const el = document.createElement("div");
  el.className = "nav-item" + (active ? " active" : "");
  el.innerHTML =
    (status ? `<span class="st st-${status}" title="${STATUS_LABEL[status] || status}"></span>`
            : `<span class="st" style="visibility:hidden"></span>`) +
    `<span class="name">${esc(label)}</span>${right}`;
  el.addEventListener("click", () => { state.view = id; renderSidebar(); renderDetail(); });
  return el;
}

// ------------------------------------------------------------------ //
//  Detail                                                              //
// ------------------------------------------------------------------ //

function renderDetail() {
  if (state.view === FINDINGS_VIEW) return renderFindings();
  const step = (state.report.results || []).find((s) => s.id === state.view);
  if (step) renderStep(step);
}

function findingCard(f) {
  return `<div class="finding sev-${f.severity}">
    <span class="sev-tag">${esc(sevLabel(f.severity))}</span>
    <div class="f-body">
      <div class="f-text">${hl(f.text)}</div>
      ${f.hint ? `<div class="f-hint">→ ${hl(f.hint)}</div>` : ""}
      ${f.step_id ? `<span class="f-step" data-step="${esc(f.step_id)}">${esc(f.step)}</span>` : ""}
    </div></div>`;
}

function renderFindings() {
  const r = state.report, d = $("#detail");
  let findings = r.findings || [];
  if (state.query) {
    const q = state.query.toLowerCase();
    findings = findings.filter((f) => (f.text + " " + f.hint + " " + f.step).toLowerCase().includes(q));
  }
  let html = `<h1 class="view-title">Findings</h1>
    <p class="sub">${findings.length} finding${findings.length === 1 ? "" : "s"}${state.query ? ` matching “${esc(state.query)}”` : ""} · ${esc(r.target)}</p>`;
  if (!findings.length) html += `<p class="note">Nothing here${state.query ? " for that search" : " yet"}.</p>`;
  findings.forEach((f) => { html += findingCard(f); });
  d.innerHTML = html;
  d.querySelectorAll(".f-step").forEach((el) =>
    el.addEventListener("click", () => { state.view = el.dataset.step; renderSidebar(); renderDetail(); d.scrollTop = 0; }));
}

function renderStep(s) {
  const d = $("#detail");
  let html = `<h1 class="view-title">${esc(s.name)}</h1>
    <p class="sub">${esc(s.category)} · phase ${s.phase}</p>`;

  if (s.command) {
    html += `<div class="step-cmd"><button class="copy-btn" id="copyCmd">copy</button>${hl(s.command)}</div>`;
    html += `<div class="status-row">
        <span class="status-chip st-${s.status}"><span class="st st-${s.status}"></span>${STATUS_LABEL[s.status] || s.status}</span>
        <span class="status-note">
          ${s.returncode !== null && s.returncode !== undefined ? `exit ${s.returncode}` : ""}
          ${s.duration ? ` · ${s.duration}s` : ""}
        </span>
      </div>`;
    if (s.status === "unsupported")
      html += `<p class="note">This flag isn't recognised by your installed version of the tool. Updating the tool usually fixes it; the command was left untouched.</p>`;
  } else {
    html += `<div class="status-row"><span class="status-chip st-${s.status}"><span class="st st-${s.status}"></span>${STATUS_LABEL[s.status] || s.status}</span></div>`;
    html += `<p class="note">${esc(s.note || "not run")}</p>`;
  }

  if (s.findings && s.findings.length) {
    html += `<div class="section-label">Findings</div>`;
    s.findings.forEach((f) => { html += findingCard({ ...f, step_id: null }); });
  }
  if (s.rows && s.rows.length) {
    html += `<div class="section-label">Parsed (${s.rows.length})</div>` + renderTable(s.columns, s.rows);
  }
  if (s.command) {
    html += `<div class="section-label">Raw output</div>`;
    const raw = s.raw_output && s.raw_output.trim() ? hl(s.raw_output)
              : `<span class="empty-raw">(no output captured)</span>`;
    html += `<pre class="raw">${raw}</pre>`;
  }

  d.innerHTML = html;
  const cp = d.querySelector("#copyCmd");
  if (cp) cp.addEventListener("click", () =>
    navigator.clipboard.writeText(s.command).then(() => {
      cp.textContent = "copied"; setTimeout(() => (cp.textContent = "copy"), 1200);
    }));
}

function renderTable(cols, rows) {
  cols = cols && cols.length ? cols : Object.keys(rows[0] || {});
  let h = `<table class="rows"><thead><tr>` + cols.map((c) => `<th>${esc(c)}</th>`).join("") + `</tr></thead><tbody>`;
  rows.forEach((row) => { h += "<tr>" + cols.map((c) => `<td>${hl(String(row[c] ?? ""))}</td>`).join("") + "</tr>"; });
  return h + "</tbody></table>";
}

// ------------------------------------------------------------------ //
//  Search                                                              //
// ------------------------------------------------------------------ //

let searchTimer = null;
$("#search").addEventListener("input", (e) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    state.query = e.target.value.trim();
    let total = 0;
    (state.report.results || []).forEach((s) => { total += stepMatchCount(s); });
    $("#searchCount").textContent = state.query ? (total ? `${total} hits` : "no hits") : "";
    renderSidebar(); renderDetail();
  }, 120);
});

// ------------------------------------------------------------------ //
//  Utils                                                               //
// ------------------------------------------------------------------ //

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function hl(s) {
  const text = esc(s);
  if (!state.query) return text;
  const q = state.query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return text.replace(new RegExp(q, "gi"), (m) => `<mark>${m}</mark>`);
}

boot();
