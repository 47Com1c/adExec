"use strict";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const FINDINGS_VIEW = "__findings__";

const state = {
  report: null,
  view: FINDINGS_VIEW,   // FINDINGS_VIEW or a step id
  query: "",
};

const $ = (sel) => document.querySelector(sel);

// ------------------------------------------------------------------ //
//  Boot                                                                //
// ------------------------------------------------------------------ //

async function boot() {
  let targets = [];
  try {
    targets = await (await fetch("/api/targets")).json();
  } catch (e) { /* ignore */ }

  if (!targets.length) {
    $("#empty").hidden = false;
    document.querySelector("main").style.display = "none";
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
  renderMeta();
  renderSummary();
  renderSidebar();
  renderDetail();
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
  const r = state.report;
  const chips = [];
  SEV_ORDER.forEach((s) => {
    const n = (r.severity_counts || {})[s] || 0;
    if (n) chips.push(`<span class="chip sev-${s}"><span class="dot"></span><b>${n}</b> ${s}</span>`);
  });
  chips.push(`<span class="chip"><b>${(r.open_ports || []).length}</b> ports</span>`);
  chips.push(`<span class="chip"><b>${(r.users || []).length}</b> users</span>`);
  chips.push(`<span class="chip"><b>${(r.shares || []).length}</b> shares</span>`);
  if (r.domain_sid) chips.push(`<span class="chip" title="Domain SID">${esc(r.domain_sid)}</span>`);
  $("#summary").innerHTML = chips.join("");
}

// ------------------------------------------------------------------ //
//  Sidebar                                                             //
// ------------------------------------------------------------------ //

function stepMatchCount(step) {
  if (!state.query) return 0;
  const q = state.query.toLowerCase();
  const hay = (step.raw_output || "").toLowerCase();
  let n = 0, i = hay.indexOf(q);
  while (i !== -1) { n++; i = hay.indexOf(q, i + q.length); }
  return n;
}

function stepMatches(step) {
  if (!state.query) return true;
  const q = state.query.toLowerCase();
  return (step.name + " " + step.category + " " + step.command + " " +
          step.raw_output + " " + step.findings.map((f) => f.text).join(" "))
         .toLowerCase().includes(q);
}

function renderSidebar() {
  const r = state.report;
  const nav = $("#sidebar");
  nav.innerHTML = "";

  // Findings entry
  const totalFindings = (r.findings || []).length;
  nav.appendChild(navItem({
    label: "Findings", id: FINDINGS_VIEW,
    right: `<span class="find-pill">${totalFindings}</span>`,
    active: state.view === FINDINGS_VIEW,
  }));

  const byCat = {};
  (r.results || []).forEach((s) => {
    if (!stepMatches(s)) return;
    (byCat[s.category] = byCat[s.category] || []).push(s);
  });

  (r.categories || []).forEach((cat) => {
    const steps = byCat[cat];
    if (!steps || !steps.length) return;
    const h = document.createElement("div");
    h.className = "nav-cat";
    h.textContent = cat;
    nav.appendChild(h);
    steps.forEach((s) => {
      const mc = stepMatchCount(s);
      nav.appendChild(navItem({
        label: s.name, id: s.id,
        statusDot: s.status,
        right: mc ? `<span class="match-badge">${mc}</span>`
                  : (s.findings.length ? `<span class="find-pill">${s.findings.length}</span>` : ""),
        active: state.view === s.id,
      }));
    });
  });
}

function navItem({ label, id, statusDot, right = "", active }) {
  const el = document.createElement("div");
  el.className = "nav-item" + (active ? " active" : "");
  el.innerHTML =
    (statusDot ? `<span class="status-dot st-${statusDot}" title="${statusDot}"></span>` : "") +
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

function renderFindings() {
  const r = state.report;
  const d = $("#detail");
  let findings = r.findings || [];
  if (state.query) {
    const q = state.query.toLowerCase();
    findings = findings.filter((f) =>
      (f.text + " " + f.hint + " " + f.step).toLowerCase().includes(q));
  }

  let html = `<h1 class="view-title">Findings</h1>
    <p class="sub">${findings.length} finding${findings.length === 1 ? "" : "s"}${state.query ? ` matching “${esc(state.query)}”` : ""} · ${r.target}</p>`;

  if (!findings.length) {
    html += `<p class="note">Nothing here${state.query ? " for that search" : " yet"}.</p>`;
  }
  findings.forEach((f) => {
    html += `<div class="finding sev-${f.severity}">
      <span class="sev-tag">${f.severity}</span>
      <div class="f-body">
        <div class="f-text">${hl(f.text)}</div>
        ${f.hint ? `<div class="f-hint">→ ${hl(f.hint)}</div>` : ""}
        <span class="f-step" data-step="${esc(f.step_id)}">${esc(f.step)}</span>
      </div></div>`;
  });
  d.innerHTML = html;
  d.querySelectorAll(".f-step").forEach((el) => {
    el.addEventListener("click", () => {
      state.view = el.dataset.step; renderSidebar(); renderDetail();
      d.scrollTop = 0;
    });
  });
}

function renderStep(s) {
  const d = $("#detail");
  let html = `<div class="step-head">
      <h1 class="view-title">${esc(s.name)}</h1>
      <p class="sub">${esc(s.category)} · phase ${s.phase}</p>
    </div>`;

  if (s.command) {
    html += `<div class="step-cmd"><button class="copy-btn" id="copyCmd">copy</button>${hl(s.command)}</div>`;
    html += `<div class="step-stats">
        <span class="badge st-${s.status}">${s.status}</span>
        ${s.returncode !== null && s.returncode !== undefined ? ` · exit ${s.returncode}` : ""}
        ${s.duration ? ` · ${s.duration}s` : ""}
      </div>`;
  } else {
    html += `<p class="note">Skipped — ${esc(s.note || "not run")}</p>`;
  }

  if (s.findings && s.findings.length) {
    html += `<div class="section-label">Findings</div>`;
    s.findings.forEach((f) => {
      html += `<div class="finding sev-${f.severity}">
        <span class="sev-tag">${f.severity}</span>
        <div class="f-body"><div class="f-text">${hl(f.text)}</div>
        ${f.hint ? `<div class="f-hint">→ ${hl(f.hint)}</div>` : ""}</div></div>`;
    });
  }

  if (s.rows && s.rows.length) {
    html += `<div class="section-label">Parsed (${s.rows.length})</div>`;
    html += renderTable(s.columns, s.rows);
  }

  if (s.command) {
    html += `<div class="section-label">Raw output</div>`;
    const raw = s.raw_output && s.raw_output.trim()
      ? hl(s.raw_output)
      : `<span class="empty-raw">(no output captured)</span>`;
    html += `<pre class="raw">${raw}</pre>`;
  }

  d.innerHTML = html;
  const cp = d.querySelector("#copyCmd");
  if (cp) cp.addEventListener("click", () => {
    navigator.clipboard.writeText(s.command).then(() => {
      cp.textContent = "copied"; setTimeout(() => (cp.textContent = "copy"), 1200);
    });
  });
}

function renderTable(cols, rows) {
  cols = cols && cols.length ? cols : Object.keys(rows[0] || {});
  let h = `<table class="rows"><thead><tr>` +
    cols.map((c) => `<th>${esc(c)}</th>`).join("") + `</tr></thead><tbody>`;
  rows.forEach((row) => {
    h += "<tr>" + cols.map((c) => `<td>${hl(String(row[c] ?? ""))}</td>`).join("") + "</tr>";
  });
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
    updateSearchCount();
    renderSidebar();
    renderDetail();
  }, 120);
});

function updateSearchCount() {
  if (!state.query) { $("#searchCount").textContent = ""; return; }
  let total = 0;
  (state.report.results || []).forEach((s) => { total += stepMatchCount(s); });
  $("#searchCount").textContent = total ? `${total} hits` : "no hits";
}

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
