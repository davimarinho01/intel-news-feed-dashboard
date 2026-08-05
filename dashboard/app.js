"use strict";

/* ==============================================================================
   Intel News Feed — Dashboard renderer
   Vanilla JS, no build step, no dependencies. Fetches data/summary.json
   (produced by modules/Dashboard.ps1) and renders every chart as plain SVG.
   Colors are set via CSS custom properties (var(--series-1) etc.) directly on
   SVG presentation attributes, so the light/dark theme toggle re-colors marks
   automatically without re-rendering.
   ============================================================================== */

const SVG_NS = "http://www.w3.org/2000/svg";

// Fixed identity → color mapping. Order never changes and is never derived
// from a given day's counts (color follows the entity, not its rank).
const SOURCE_ORDER = [
  "The Hacker News",
  "BleepingComputer",
  "Krebs on Security",
  "Dark Reading",
  "CISA Advisories",
];
const SERIES_VARS = ["--series-1", "--series-2", "--series-3", "--series-4", "--series-5"];

const ICONS = {
  critical: '<svg viewBox="0 0 16 16"><path d="M8 2 14.5 13.5H1.5Z" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round"/><line x1="8" y1="6.3" x2="8" y2="9.4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/><circle cx="8" cy="11.4" r="0.8" fill="currentColor"/></svg>',
  high: '<svg viewBox="0 0 16 16"><rect x="3.3" y="3.3" width="9.4" height="9.4" rx="1.5" transform="rotate(45 8 8)" fill="none" stroke="currentColor" stroke-width="1.3"/><line x1="8" y1="5.7" x2="8" y2="8.4" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/><circle cx="8" cy="10.4" r="0.8" fill="currentColor"/></svg>',
  medium: '<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="6.2" fill="none" stroke="currentColor" stroke-width="1.3"/><line x1="5.4" y1="8" x2="10.6" y2="8" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>',
  low: '<svg viewBox="0 0 16 16"><circle cx="8" cy="8" r="6.2" fill="none" stroke="currentColor" stroke-width="1.3"/><path d="M5.2 8.2 7.1 10 10.8 6" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>',
};

const SEVERITY_CONFIG = {
  Critical: { cls: "critical", ptLabel: "Crítica", cssVar: "--status-critical", icon: ICONS.critical },
  High: { cls: "high", ptLabel: "Alta", cssVar: "--status-serious", icon: ICONS.high },
  Medium: { cls: "medium", ptLabel: "Média", cssVar: "--status-warning", icon: ICONS.medium },
  Low: { cls: "low", ptLabel: "Baixa", cssVar: "--status-good", icon: ICONS.low },
};
const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"];

// ---------- small DOM helpers ----------

function el(tag, attrs, children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [key, value] of Object.entries(attrs)) {
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value; // data always goes through textContent
      else if (key === "html") node.innerHTML = value; // only ever used with static, hardcoded strings
      else node.setAttribute(key, value);
    }
  }
  (children || []).forEach((child) => {
    if (child) node.appendChild(child);
  });
  return node;
}

function svgEl(tag, attrs) {
  const node = document.createElementNS(SVG_NS, tag);
  if (attrs) {
    for (const [key, value] of Object.entries(attrs)) {
      node.setAttribute(key, value);
    }
  }
  return node;
}

function safeHref(url) {
  if (typeof url === "string" && /^https?:\/\//i.test(url)) return url;
  return "#";
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function seriesVarFor(sourceName) {
  const idx = SOURCE_ORDER.indexOf(sourceName);
  return idx >= 0 ? `var(${SERIES_VARS[idx]})` : "var(--text-muted)";
}

function formatDateTime(iso) {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString("pt-BR", {
    day: "2-digit", month: "2-digit", year: "numeric",
    hour: "2-digit", minute: "2-digit", timeZone: "UTC",
  }) + " UTC";
}

function formatDate(iso) {
  const d = new Date(iso + "T00:00:00Z");
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleDateString("pt-BR", { day: "2-digit", month: "2-digit", timeZone: "UTC" });
}

// ---------- KPI row ----------

function renderKpiRow(container, data) {
  clear(container);
  const bySeverity = {};
  data.SeverityBreakdown.forEach((s) => { bySeverity[s.Severity] = s.Count; });

  const tiles = [
    { label: "Total de artigos monitorados", value: data.TotalArticles },
    { label: "Achados críticos", value: bySeverity.Critical || 0, severity: "Critical" },
    { label: "Achados de alta severidade", value: bySeverity.High || 0, severity: "High" },
    { label: "Fontes acompanhadas", value: data.SourceBreakdown.length },
  ];

  tiles.forEach((tile) => {
    const valueChildren = [document.createTextNode(String(tile.value))];
    if (tile.severity) {
      const cfg = SEVERITY_CONFIG[tile.severity];
      const icon = el("span", { class: "stat-icon", html: cfg.icon });
      icon.style.color = `var(${cfg.cssVar})`;
      valueChildren.unshift(icon);
    }
    const card = el("div", { class: "card stat-tile" }, [
      el("p", { class: "stat-label", text: tile.label }),
      el("div", { class: "stat-value" }, valueChildren),
    ]);
    container.appendChild(card);
  });
}

// ---------- Severity chart (status colors) ----------

function renderSeverityChart(container, data) {
  clear(container);
  const bySeverity = {};
  data.SeverityBreakdown.forEach((s) => { bySeverity[s.Severity] = s.Count; });
  const maxVal = Math.max(1, ...SEVERITY_ORDER.map((k) => bySeverity[k] || 0));

  const grid = el("div", { class: "severity-chart" });
  SEVERITY_ORDER.forEach((level) => {
    const cfg = SEVERITY_CONFIG[level];
    const count = bySeverity[level] || 0;
    const heightPct = Math.max(2, (count / maxVal) * 100);

    const bar = el("div", { class: "severity-bar" });
    bar.style.height = heightPct + "%";
    bar.style.background = `var(${cfg.cssVar})`;

    const icon = el("span", { html: cfg.icon });
    icon.style.color = `var(${cfg.cssVar})`;

    const col = el("div", { class: "severity-col" }, [
      el("div", { class: "severity-value", text: String(count) }),
      el("div", { class: "severity-bar-wrap" }, [bar]),
      el("div", { class: "severity-tag" }, [icon, el("span", { text: cfg.ptLabel })]),
    ]);
    grid.appendChild(col);
  });
  container.appendChild(grid);
}

// ---------- Generic horizontal bar chart (source / CVE / keyword) ----------

function renderHorizontalBars(container, items, options) {
  clear(container);
  if (!items.length) {
    container.appendChild(el("p", { class: "empty-state", text: "Sem dados suficientes ainda." }));
    return;
  }
  const maxVal = Math.max(1, ...items.map(options.getValue));

  items.forEach((item) => {
    const value = options.getValue(item);
    const widthPct = (value / maxVal) * 82; // reserve ~18% so the value label never clips

    const fill = el("div", { class: "bar-fill" });
    fill.style.width = widthPct + "%";
    fill.style.background = options.getColor(item);

    const valueLabel = el("div", { class: "bar-value", text: String(value) });
    valueLabel.style.left = widthPct + "%";

    const track = el("div", { class: "bar-track" }, [fill, valueLabel]);
    const label = el("span", { class: "bar-label", text: options.getLabel(item) });
    if (options.getTitle) label.setAttribute("title", options.getTitle(item));

    const row = el("div", { class: "bar-row" }, [label, track]);

    const href = options.getHref ? options.getHref(item) : null;
    if (href) {
      const link = el("a", { href: safeHref(href), target: "_blank", rel: "noopener" }, [row]);
      link.style.display = "contents";
      container.appendChild(link);
    } else {
      container.appendChild(row);
    }
  });
}

function renderSourceChart(container, data) {
  renderHorizontalBars(container, data.SourceBreakdown, {
    getLabel: (d) => d.Source,
    getValue: (d) => d.Count,
    getColor: () => "var(--series-1)",
  });
}

function renderCveChart(container, data) {
  renderHorizontalBars(container, data.TopCves, {
    getLabel: (d) => d.Cve,
    getValue: (d) => d.Count,
    getColor: (d) => {
      const cfg = SEVERITY_CONFIG[d.Severity];
      return cfg ? `var(${cfg.cssVar})` : "var(--text-muted)";
    },
    getHref: (d) => d.Url,
    getTitle: (d) => `${d.Cve} — ${d.Severity || "sem severidade"}`,
  });
}

function renderKeywordChart(container, data) {
  renderHorizontalBars(container, data.TopKeywords, {
    getLabel: (d) => d.Keyword,
    getValue: (d) => d.Count,
    getColor: () => "var(--series-1)",
  });
}

// ---------- Daily trend line chart ----------

function renderTrendChart(container, dailyTrend) {
  clear(container);
  const labels = dailyTrend.Labels || [];
  const datasets = dailyTrend.Datasets || [];

  if (!labels.length || !datasets.length) {
    container.appendChild(el("p", { class: "empty-state", text: "Sem histórico suficiente ainda para uma tendência." }));
    return;
  }

  // Order datasets by the fixed source order; unknown sources fall back to muted gray.
  const orderedDatasets = [...datasets].sort(
    (a, b) => SOURCE_ORDER.indexOf(a.Source) - SOURCE_ORDER.indexOf(b.Source)
  );

  // --- legend ---
  const legend = el("div", { class: "trend-legend" });
  orderedDatasets.forEach((ds) => {
    const swatch = el("span", { class: "trend-legend-swatch" });
    swatch.style.background = seriesVarFor(ds.Source);
    legend.appendChild(el("span", { class: "trend-legend-item" }, [swatch, el("span", { text: ds.Source })]));
  });

  // --- geometry ---
  const width = 960;
  const height = 260;
  const margin = { top: 12, right: 16, bottom: 26, left: 34 };
  const plotW = width - margin.left - margin.right;
  const plotH = height - margin.top - margin.bottom;

  const maxVal = Math.max(1, ...orderedDatasets.flatMap((d) => d.Data));
  const xStep = labels.length > 1 ? plotW / (labels.length - 1) : 0;
  const xAt = (i) => margin.left + i * xStep;
  const yAt = (v) => margin.top + plotH - (v / maxVal) * plotH;

  const svg = svgEl("svg", {
    class: "trend-svg",
    viewBox: `0 0 ${width} ${height}`,
    role: "img",
    "aria-label": "Gráfico de linha: artigos publicados por dia, por fonte",
  });

  // gridlines (0, mid, max) + y labels
  [0, 0.5, 1].forEach((t) => {
    const v = maxVal * t;
    const y = yAt(v);
    svg.appendChild(svgEl("line", { class: "trend-gridline", x1: margin.left, x2: width - margin.right, y1: y, y2: y }));
    const label = svgEl("text", { class: "trend-axis-label", x: margin.left - 8, y: y + 3, "text-anchor": "end" });
    label.textContent = String(Math.round(v));
    svg.appendChild(label);
  });

  // x-axis baseline + a handful of evenly spaced date ticks
  svg.appendChild(svgEl("line", {
    class: "trend-gridline", x1: margin.left, x2: width - margin.right,
    y1: margin.top + plotH, y2: margin.top + plotH,
  }));
  const tickCount = Math.min(6, labels.length);
  for (let t = 0; t < tickCount; t++) {
    const idx = tickCount === 1 ? 0 : Math.round((t / (tickCount - 1)) * (labels.length - 1));
    const label = svgEl("text", {
      class: "trend-axis-label", x: xAt(idx), y: height - 6, "text-anchor": "middle",
    });
    label.textContent = formatDate(labels[idx]);
    svg.appendChild(label);
  }

  // series lines
  orderedDatasets.forEach((ds) => {
    const points = ds.Data.map((v, i) => `${xAt(i)},${yAt(v)}`).join(" L ");
    const path = svgEl("path", {
      d: `M ${points}`, fill: "none", stroke: seriesVarFor(ds.Source),
      "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round",
    });
    svg.appendChild(path);
  });

  // crosshair + hover dots (one per series, hidden until pointermove)
  const crosshair = svgEl("line", {
    class: "trend-crosshair", x1: 0, x2: 0, y1: margin.top, y2: margin.top + plotH,
  });
  svg.appendChild(crosshair);

  const hoverDots = orderedDatasets.map((ds) => {
    const dot = svgEl("circle", { class: "trend-hover-dot", r: 4, stroke: seriesVarFor(ds.Source) });
    dot.style.fill = "var(--surface-1)";
    svg.appendChild(dot);
    return dot;
  });

  // hit layer + tooltip
  const hitLayer = svgEl("rect", {
    class: "trend-hit-layer", x: margin.left, y: margin.top, width: plotW, height: plotH,
  });
  svg.appendChild(hitLayer);

  const tooltip = el("div", { class: "trend-tooltip" });
  const tooltipDate = el("div", { class: "trend-tooltip-date" });
  tooltip.appendChild(tooltipDate);
  const tooltipRows = orderedDatasets.map((ds) => {
    const key = el("span", { class: "trend-tooltip-line" });
    key.style.background = seriesVarFor(ds.Source);
    const nameEl = el("span", { text: ds.Source });
    const valEl = el("span", { class: "trend-tooltip-val" });
    const row = el("div", { class: "trend-tooltip-row" }, [
      el("span", { class: "trend-tooltip-key" }, [key, nameEl]),
      valEl,
    ]);
    tooltip.appendChild(row);
    return { valEl };
  });

  const wrap = el("div", { class: "trend-chart-wrap" }, [svg, tooltip]);

  function showAt(index) {
    const x = xAt(index);
    crosshair.setAttribute("x1", x);
    crosshair.setAttribute("x2", x);
    crosshair.style.opacity = "1";

    orderedDatasets.forEach((ds, i) => {
      const v = ds.Data[index];
      hoverDots[i].setAttribute("cx", x);
      hoverDots[i].setAttribute("cy", yAt(v));
      hoverDots[i].style.opacity = "1";
      tooltipRows[i].valEl.textContent = String(v);
    });
    tooltipDate.textContent = formatDate(labels[index]);

    const pct = (x / width) * 100;
    tooltip.style.left = `clamp(80px, ${pct}%, calc(100% - 80px))`;
    tooltip.style.top = `${((margin.top + 6) / height) * 100}%`;
    tooltip.style.opacity = "1";
  }

  function hide() {
    crosshair.style.opacity = "0";
    hoverDots.forEach((d) => { d.style.opacity = "0"; });
    tooltip.style.opacity = "0";
  }

  function handlePointer(evt) {
    const rect = svg.getBoundingClientRect();
    const relX = ((evt.clientX - rect.left) / rect.width) * width;
    let index = xStep > 0 ? Math.round((relX - margin.left) / xStep) : 0;
    index = Math.max(0, Math.min(labels.length - 1, index));
    showAt(index);
  }

  hitLayer.addEventListener("pointermove", handlePointer);
  hitLayer.addEventListener("pointerleave", hide);
  hitLayer.addEventListener("pointerdown", handlePointer);

  container.appendChild(legend);
  container.appendChild(wrap);
}

function buildTrendTable(container, dailyTrend) {
  clear(container);
  const labels = dailyTrend.Labels || [];
  const datasets = dailyTrend.Datasets || [];
  if (!labels.length || !datasets.length) {
    container.appendChild(el("p", { class: "empty-state", text: "Sem histórico suficiente ainda." }));
    return;
  }
  const orderedDatasets = [...datasets].sort(
    (a, b) => SOURCE_ORDER.indexOf(a.Source) - SOURCE_ORDER.indexOf(b.Source)
  );

  const thead = el("thead", null, [
    el("tr", null, [
      el("th", { text: "Data" }),
      ...orderedDatasets.map((ds) => el("th", { text: ds.Source })),
    ]),
  ]);

  const tbody = el("tbody");
  // Most recent day first for a table (reading order matches the rest of the dashboard).
  for (let i = labels.length - 1; i >= 0; i--) {
    const row = el("tr", null, [
      el("td", { text: formatDate(labels[i]) }),
      ...orderedDatasets.map((ds) => el("td", { class: "num", text: String(ds.Data[i]) })),
    ]);
    tbody.appendChild(row);
  }

  const table = el("table", { class: "data-table" }, [thead, tbody]);
  container.appendChild(table);
}

// ---------- Recent critical/high findings table ----------

function renderRecentTable(container, items) {
  clear(container);
  if (!items.length) {
    container.appendChild(el("p", { class: "empty-state", text: "Nenhum achado Critical/High no histórico atual." }));
    return;
  }

  const thead = el("thead", null, [
    el("tr", null, [
      el("th", { text: "Severidade" }),
      el("th", { text: "Título" }),
      el("th", { text: "Fonte" }),
      el("th", { text: "Publicado" }),
      el("th", { text: "CVEs" }),
    ]),
  ]);

  const tbody = el("tbody");
  items.forEach((item) => {
    const cfg = SEVERITY_CONFIG[item.Severity];
    const badge = el("span", { class: `severity-badge ${cfg ? cfg.cls : ""}` }, [
      el("span", { html: cfg ? cfg.icon : "" }),
      el("span", { text: item.Severity || "—" }),
    ]);

    const titleLink = el("a", { href: safeHref(item.Url), target: "_blank", rel: "noopener", text: item.Title });

    const cveCell = el("td");
    if (item.Cves && item.Cves.length) {
      item.Cves.forEach((cve) => cveCell.appendChild(el("span", { class: "cve-chip", text: cve })));
    } else {
      cveCell.textContent = "—";
    }

    const row = el("tr", null, [
      el("td", null, [badge]),
      el("td", null, [titleLink]),
      el("td", { text: item.Source }),
      el("td", { text: formatDateTime(item.PublishedAt) }),
      cveCell,
    ]);
    tbody.appendChild(row);
  });

  container.appendChild(el("table", { class: "data-table" }, [thead, tbody]));
}

// ---------- theme toggle ----------

function currentIsDark(root) {
  const attr = root.getAttribute("data-theme");
  if (attr === "dark") return true;
  if (attr === "light") return false;
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function setupThemeToggle() {
  const root = document.documentElement;
  const stored = localStorage.getItem("intel-theme");
  if (stored === "light" || stored === "dark") root.setAttribute("data-theme", stored);

  const button = document.getElementById("theme-toggle");
  const label = document.getElementById("theme-toggle-label");

  function sync() {
    const dark = currentIsDark(root);
    label.textContent = dark ? "Modo claro" : "Modo escuro";
    button.setAttribute("aria-pressed", String(dark));
  }

  button.addEventListener("click", () => {
    const next = currentIsDark(root) ? "light" : "dark";
    root.setAttribute("data-theme", next);
    localStorage.setItem("intel-theme", next);
    sync();
  });

  sync();
}

// ---------- table-view toggle for the trend chart ----------

function setupTrendToggle() {
  const button = document.getElementById("trend-table-toggle");
  const chartEl = document.getElementById("trend-chart");
  const tableEl = document.getElementById("trend-table");

  button.addEventListener("click", () => {
    const showingTable = tableEl.style.display !== "none";
    tableEl.style.display = showingTable ? "none" : "block";
    chartEl.style.display = showingTable ? "block" : "none";
    button.setAttribute("aria-pressed", String(!showingTable));
    button.textContent = showingTable ? "Ver como tabela" : "Ver como gráfico";
  });
}

// ---------- boot ----------

function renderHeader(data) {
  const subtitle = document.getElementById("header-subtitle");
  subtitle.textContent =
    `Atualizado em ${formatDateTime(data.GeneratedAt)} · ${data.TotalArticles} artigos na base histórica`;
  document.getElementById("footer-total").textContent =
    `${data.TotalArticles} artigos indexados`;
}

function renderDashboard(data) {
  renderHeader(data);
  renderKpiRow(document.getElementById("kpi-row"), data);
  renderSeverityChart(document.getElementById("severity-chart"), data);
  renderSourceChart(document.getElementById("source-chart"), data);
  renderTrendChart(document.getElementById("trend-chart"), data.DailyTrend);
  buildTrendTable(document.getElementById("trend-table"), data.DailyTrend);
  renderCveChart(document.getElementById("cve-chart"), data);
  renderKeywordChart(document.getElementById("keyword-chart"), data);
  renderRecentTable(document.getElementById("recent-table"), data.RecentCritical);
}

function showLoadError(err) {
  const subtitle = document.getElementById("header-subtitle");
  subtitle.textContent = "Não foi possível carregar data/summary.json.";
  const root = document.getElementById("dashboard-root");
  clear(root);
  root.appendChild(el("div", { class: "card" }, [
    el("p", { class: "empty-state", text: "Nenhum dado disponível ainda. Rode o pipeline (IntelNewsFeed.ps1) ao menos uma vez para gerar data/summary.json." }),
  ]));
  console.error("Failed to load dashboard data:", err);
}

async function boot() {
  setupThemeToggle();
  setupTrendToggle();
  try {
    const res = await fetch("data/summary.json", { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderDashboard(data);
  } catch (err) {
    showLoadError(err);
  }
}

boot();
