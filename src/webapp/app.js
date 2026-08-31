// Dashboard frontend: polls the stdlib JSON API in web_server.py and
// renders stat tiles, charts, and tables. Deliberately uses textContent
// (never innerHTML) for anything derived from a detection message, process
// name, or file hash - those can legitimately contain attacker-controlled
// strings (e.g. a malicious CommandLine), so treat them as data, not markup.

const POLL_MS = 2000;
const COLORS = { critical: "#ff4d4d", warning: "#ffb020", info: "#6c7280", accent: "#3aa0ff" };

let lastAlerts = [];
let lastActivity = [];
let charts = {};

async function getJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}

function el(tag, opts = {}) {
  const node = document.createElement(tag);
  if (opts.text !== undefined) node.textContent = opts.text;
  if (opts.className) node.className = opts.className;
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function emptyRow(colSpan, label) {
  const tr = el("tr", { className: "empty-row" });
  const td = el("td", { text: label });
  td.colSpan = colSpan;
  tr.appendChild(td);
  return tr;
}

// ---- stat tiles ----------------------------------------------------------
function renderSummary(summary) {
  document.getElementById("statTotalAlerts").textContent = summary.total_alerts;
  document.getElementById("statCritical").textContent = summary.critical_count;
  document.getElementById("statWarning").textContent = summary.warning_count;
  document.getElementById("statProcesses").textContent = summary.processes_monitored;
  document.getElementById("statSamples").textContent = summary.samples_scanned;

  document.getElementById("statTelemetry").textContent = summary.telemetry_events_seen;
  const lastEventEl = document.getElementById("statLastEvent");
  const dot = document.getElementById("liveDot");
  const age = summary.seconds_since_last_event;
  if (age === null || age === undefined) {
    lastEventEl.textContent = "no events yet";
    dot.className = "live-dot";
  } else if (age < 10) {
    lastEventEl.textContent = "live";
    dot.className = "live-dot live";
  } else {
    lastEventEl.textContent = `last ${Math.round(age)}s ago`;
    dot.className = "live-dot stale";
  }

  const badge = document.getElementById("sensorStatus");
  badge.textContent = summary.sensor_status;
  let badgeClass = "badge-ok";
  if (summary.sensor_status.includes("unavailable")) {
    badgeClass = "badge-off";
  } else if (summary.sysmon_stale || summary.etw_stale) {
    badgeClass = "badge-warn";
  }
  badge.className = "badge " + badgeClass;
}

// ---- charts ---------------------------------------------------------------
function initCharts() {
  charts.timeseries = new Chart(document.getElementById("timeseriesChart"), {
    type: "bar",
    data: {
      labels: [],
      datasets: [
        { label: "Critical", data: [], backgroundColor: COLORS.critical },
        { label: "Warning", data: [], backgroundColor: COLORS.warning },
        { label: "Info", data: [], backgroundColor: COLORS.info },
      ],
    },
    options: {
      responsive: true,
      scales: { x: { stacked: true, ticks: { color: "#9aa0a6" } }, y: { stacked: true, beginAtZero: true, ticks: { color: "#9aa0a6" } } },
      plugins: { legend: { labels: { color: "#e6e6e6" } } },
    },
  });

  charts.category = new Chart(document.getElementById("categoryChart"), {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [], backgroundColor: ["#3aa0ff", "#ff4d4d", "#ffb020", "#6c7280", "#8e6cff", "#2ecc71", "#e67e22"] }] },
    options: { responsive: true, plugins: { legend: { position: "bottom", labels: { color: "#e6e6e6", boxWidth: 10, font: { size: 10 } } } } },
  });

  charts.process = new Chart(document.getElementById("processChart"), {
    type: "bar",
    data: { labels: [], datasets: [{ label: "Threat score", data: [], backgroundColor: COLORS.accent }] },
    options: {
      indexAxis: "y",
      responsive: true,
      scales: { x: { beginAtZero: true, max: 100, ticks: { color: "#9aa0a6" } }, y: { ticks: { color: "#9aa0a6" } } },
      plugins: { legend: { display: false } },
    },
  });
}

function renderTimeseries(ts) {
  const c = charts.timeseries;
  c.data.labels = ts.labels;
  c.data.datasets[0].data = ts.critical;
  c.data.datasets[1].data = ts.warning;
  c.data.datasets[2].data = ts.info;
  c.update("none");
}

function renderCategories(cats) {
  const c = charts.category;
  c.data.labels = Object.keys(cats);
  c.data.datasets[0].data = Object.values(cats);
  c.update("none");
}

function renderProcessChart(rows) {
  const top = rows.slice(0, 5);
  const c = charts.process;
  c.data.labels = top.map((r) => `${r.name} (${r.pid})`);
  c.data.datasets[0].data = top.map((r) => r.score);
  c.update("none");
}

// ---- detections table -------------------------------------------------
function renderAlerts() {
  const body = document.getElementById("alertsBody");
  const textFilter = document.getElementById("alertFilter").value.toLowerCase();
  const sevFilter = document.getElementById("severityFilter").value;

  const rows = lastAlerts.filter((a) => {
    if (sevFilter && a.severity !== sevFilter) return false;
    if (textFilter && !a.message.toLowerCase().includes(textFilter)) return false;
    return true;
  });

  clear(body);
  if (rows.length === 0) {
    body.appendChild(emptyRow(4, "No detections match this filter."));
    return;
  }
  for (const a of rows.slice(0, 200)) {
    const tr = el("tr");
    tr.appendChild(el("td", { text: a.time }));
    tr.appendChild(el("td", { text: a.severity, className: `sev-${a.severity}` }));
    tr.appendChild(el("td", { text: a.category }));
    tr.appendChild(el("td", { text: a.message }));
    body.appendChild(tr);
  }
}

// ---- endpoint processes table ------------------------------------------
function renderProcesses(rows) {
  const body = document.getElementById("processBody");
  clear(body);
  if (rows.length === 0) {
    body.appendChild(emptyRow(5, "No scored processes yet."));
    return;
  }
  for (const r of rows) {
    const tr = el("tr");
    tr.appendChild(el("td", { text: r.pid }));
    tr.appendChild(el("td", { text: r.name }));
    tr.appendChild(el("td", { text: r.score }));
    tr.appendChild(el("td", { text: r.verdict, className: `sev-${r.verdict === "CRITICAL" ? "CRITICAL" : r.verdict === "SUSPICIOUS" ? "WARNING" : "INFO"}` }));
    const actionTd = el("td");
    const btn = el("button", { text: "Terminate", className: "btn btn-danger-outline btn-small" });
    btn.addEventListener("click", () => terminateProcess(r.pid, r.name));
    actionTd.appendChild(btn);
    tr.appendChild(actionTd);
    body.appendChild(tr);
  }
}

async function terminateProcess(pid, name) {
  if (!confirm(`Suspend and terminate ${name} (PID ${pid})?`)) return;
  await fetch(`/api/processes/${pid}/terminate`, { method: "POST" });
  poll();
}

// ---- static analysis table ----------------------------------------------
function renderStatic(rows) {
  const body = document.getElementById("staticBody");
  clear(body);
  if (rows.length === 0) {
    body.appendChild(emptyRow(4, "No static findings yet."));
    return;
  }
  for (const r of rows) {
    const tr = el("tr");
    tr.appendChild(el("td", { text: r.file }));
    tr.appendChild(el("td", { text: r.hash }));
    tr.appendChild(el("td", { text: r.score }));
    tr.appendChild(el("td", { text: r.verdict, className: `sev-${r.verdict === "MALICIOUS" ? "CRITICAL" : r.verdict === "SUSPICIOUS" ? "WARNING" : "INFO"}` }));
    body.appendChild(tr);
  }
}

// ---- process explorer (every launch, flagged or not) --------------------
function renderExplorer() {
  const body = document.getElementById("explorerBody");
  const filter = document.getElementById("explorerFilter").value.toLowerCase();

  const rows = lastActivity.filter((e) => {
    if (!filter) return true;
    return [e.image, e.parent_image, e.command_line, e.lineage].some((f) => (f || "").toLowerCase().includes(filter));
  });

  clear(body);
  if (rows.length === 0) {
    body.appendChild(emptyRow(6, lastActivity.length === 0 ? "No process activity observed yet - needs an elevated, Sysmon-connected run." : "No activity matches this filter."));
    return;
  }
  for (const e of rows.slice(0, 300)) {
    const tr = el("tr");
    tr.appendChild(el("td", { text: e.time }));
    tr.appendChild(el("td", { text: e.pid }));
    tr.appendChild(el("td", { text: e.image || "" }));
    const source = e.source || "sysmon";
    tr.appendChild(el("td", { text: source, className: `src-${source}` }));
    tr.appendChild(el("td", { text: e.lineage || "" }));
    tr.appendChild(el("td", { text: e.command_line || "" }));
    body.appendChild(tr);
  }
}

// ---- rules tab (additive YAML rule pack) ---------------------------------
function renderRules(rows) {
  const body = document.getElementById("rulesBody");
  clear(body);
  if (rows.length === 0) {
    body.appendChild(emptyRow(6, "No custom rules loaded - add a YAML file under rules/custom/."));
    return;
  }
  for (const r of rows) {
    const tr = el("tr");
    tr.appendChild(el("td", { text: r.name }));
    tr.appendChild(el("td", { text: r.technique || "" }));
    tr.appendChild(el("td", { text: r.applies_to }));
    tr.appendChild(el("td", { text: r.score }));
    tr.appendChild(el("td", { text: r.enabled ? "Enabled" : "Disabled", className: r.enabled ? "sev-INFO" : "sev-WARNING" }));
    tr.appendChild(el("td", { text: r.hit_count }));
    body.appendChild(tr);
  }
}

// ---- tabs -----------------------------------------------------------------
function initTabs() {
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach((c) => c.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
    });
  });
}

// ---- polling loop -----------------------------------------------------
async function poll() {
  try {
    const [summary, alerts, timeseries, categories, processes, staticRows, activity, rules] = await Promise.all([
      getJSON("/api/summary"),
      getJSON("/api/alerts?limit=200"),
      getJSON("/api/alerts/timeseries"),
      getJSON("/api/alerts/categories"),
      getJSON("/api/processes"),
      getJSON("/api/static"),
      getJSON("/api/process-activity?limit=300"),
      getJSON("/api/rules"),
    ]);
    renderSummary(summary);
    lastAlerts = alerts;
    renderAlerts();
    renderTimeseries(timeseries);
    renderCategories(categories);
    renderProcessChart(processes);
    renderProcesses(processes);
    renderStatic(staticRows);
    lastActivity = activity;
    renderExplorer();
    renderRules(rules);
  } catch (e) {
    console.error("poll failed", e);
  }
}

async function isolateHost() {
  if (!confirm("Isolate this host from the network? (simulated - no real firewall changes are made)")) return;
  await fetch("/api/host/isolate", { method: "POST" });
}

document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  initTabs();
  document.getElementById("alertFilter").addEventListener("input", renderAlerts);
  document.getElementById("severityFilter").addEventListener("change", renderAlerts);
  document.getElementById("explorerFilter").addEventListener("input", renderExplorer);
  document.getElementById("isolateBtn").addEventListener("click", isolateHost);
  poll();
  setInterval(poll, POLL_MS);
});
