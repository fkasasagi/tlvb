/* FindEvil Examiner Portal — vanilla JS SPA.
   Hash-based router: #/ → dashboard; #/cases/<id>[?tab=findings] → detail.
   No frameworks. No external CDN. Talks to /api over fetch. */

"use strict";

// ----- i18n (Wave 32) -------------------------------------------------------
// Minimal label localisation: t("key") returns the current-locale string,
// falling back to the key itself if missing (so untranslated UI bits are
// instantly visible during dev). Locale persists in localStorage so the
// examiner's choice survives reload.
//
// Scope is intentionally narrow: tab names, pipeline buttons, modal headers.
// Long examiner-facing prose (Recommendations bullets, error messages,
// tooltips) stays in the source language — Tier 3 report locale handles
// those separately (Wave 26).

const I18N_DICT = {
  ja: {
    "tab.status":      "Status",
    "tab.events":      "Events",
    "tab.findings":    "Findings",
    "tab.timeline":    "Timeline",
    "tab.iocs":        "IOC",
    "tab.mitre":       "MITRE Map",
    "tab.report":      "Report",
    "tab.audit":       "Audit",
    "btn.autopilot":   "🤖 Auto-pilot",
    "btn.parse":       "Parse",
    "btn.analyze":     "Analyze All",
    "btn.synthesize":  "Synthesize",
    "btn.report":      "Generate Report",
    "lang.label":      "言語",
  },
  en: {
    "tab.status":      "Status",
    "tab.events":      "Events",
    "tab.findings":    "Findings",
    "tab.timeline":    "Timeline",
    "tab.iocs":        "IOC",
    "tab.mitre":       "MITRE Map",
    "tab.report":      "Report",
    "tab.audit":       "Audit",
    "btn.autopilot":   "🤖 Auto-pilot",
    "btn.parse":       "Parse",
    "btn.analyze":     "Analyze All",
    "btn.synthesize":  "Synthesize",
    "btn.report":      "Generate Report",
    "lang.label":      "Language",
  },
  // Wave 35: zh / ko / es. Tab + button labels only; long prose stays in
  // the source language until DESIGN v0.3 #9 full locale rollout.
  zh: {
    "tab.status":      "状态",
    "tab.events":      "事件",
    "tab.findings":    "发现",
    "tab.timeline":    "时间线",
    "tab.iocs":        "IOC",
    "tab.mitre":       "MITRE 映射",
    "tab.report":      "报告",
    "tab.audit":       "审计",
    "btn.autopilot":   "🤖 自动驾驶",
    "btn.parse":       "解析",
    "btn.analyze":     "全部分析",
    "btn.synthesize":  "合成",
    "btn.report":      "生成报告",
    "lang.label":      "语言",
  },
  ko: {
    "tab.status":      "상태",
    "tab.events":      "이벤트",
    "tab.findings":    "발견",
    "tab.timeline":    "타임라인",
    "tab.iocs":        "IOC",
    "tab.mitre":       "MITRE 매핑",
    "tab.report":      "보고서",
    "tab.audit":       "감사",
    "btn.autopilot":   "🤖 자동조종",
    "btn.parse":       "파싱",
    "btn.analyze":     "전체 분석",
    "btn.synthesize":  "통합",
    "btn.report":      "보고서 생성",
    "lang.label":      "언어",
  },
  es: {
    "tab.status":      "Estado",
    "tab.events":      "Eventos",
    "tab.findings":    "Hallazgos",
    "tab.timeline":    "Cronología",
    "tab.iocs":        "IOC",
    "tab.mitre":       "Mapa MITRE",
    "tab.report":      "Informe",
    "tab.audit":       "Auditoría",
    "btn.autopilot":   "🤖 Piloto automático",
    "btn.parse":       "Analizar",
    "btn.analyze":     "Analizar todo",
    "btn.synthesize":  "Sintetizar",
    "btn.report":      "Generar informe",
    "lang.label":      "Idioma",
  },
};

function currentLocale() {
  return localStorage.getItem("findevil_locale") || "ja";
}
function setLocale(lang) {
  localStorage.setItem("findevil_locale", lang);
  location.reload();  // simplest re-render strategy
}
function t(key) {
  const dict = I18N_DICT[currentLocale()] || I18N_DICT.ja;
  return dict[key] || key;
}


// ----- tiny DOM helpers ------------------------------------------------------
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const h = (tag, attrs = {}, children = []) => {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") el.className = v;
    else if (k === "html") el.innerHTML = v;
    else if (k.startsWith("on") && typeof v === "function")
      el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (v != null) el.setAttribute(k, v);
  }
  for (const c of [].concat(children || [])) {
    if (c == null) continue;
    el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return el;
};
const escapeHTML = (s) => String(s ?? "")
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;")
  .replace(/"/g, "&quot;");

const fmtTS = (ts) => {
  if (!ts) return "—";
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
  } catch (_) { return ts; }
};

// ----- API ------------------------------------------------------------------
async function api(method, path, body) {
  const init = { method, headers: {} };
  if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  const r = await fetch(path, init);
  const ct = r.headers.get("content-type") || "";
  if (!r.ok) {
    let msg = r.status + " " + r.statusText;
    if (ct.includes("application/json")) {
      try { const j = await r.json(); if (j.error) msg = j.error; } catch (_) {}
    } else {
      try { msg = (await r.text()).slice(0, 200) || msg; } catch (_) {}
    }
    throw new Error(msg);
  }
  if (ct.includes("application/json")) return r.json();
  return r.text();
}

// ----- toast / modal --------------------------------------------------------
let toastTimer = null;
function toast(msg, kind = "info") {
  const el = $("#toast");
  el.className = "toast " + kind;
  el.textContent = msg;
  el.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add("hidden"), 4000);
}

function modal(content, opts = {}) {
  const shade = $("#modal");
  shade.innerHTML = "";
  const wrap = h("div", { class: "modal" }, content);
  shade.appendChild(wrap);
  shade.classList.remove("hidden");
  const close = () => shade.classList.add("hidden");
  shade.onclick = (ev) => { if (ev.target === shade && !opts.persistent) close(); };
  return close;
}

// ----- router ---------------------------------------------------------------
const routes = [];
function route(pattern, render) { routes.push({ pattern, render }); }

function parseHash() {
  let h = window.location.hash || "#/";
  if (!h.startsWith("#")) h = "#" + h;
  const [path, query] = h.slice(1).split("?");
  const params = {};
  if (query) {
    for (const kv of query.split("&")) {
      const [k, v] = kv.split("=");
      params[decodeURIComponent(k)] = v == null ? "" : decodeURIComponent(v);
    }
  }
  return { path: path || "/", params };
}

async function dispatch() {
  const { path, params } = parseHash();
  for (const r of routes) {
    const m = path.match(r.pattern);
    if (m) {
      try { await r.render({ args: m.slice(1), params }); }
      catch (e) { showError(e); }
      return;
    }
  }
  $("#app").innerHTML = `<div class="empty">No route for ${escapeHTML(path)}</div>`;
}

window.addEventListener("hashchange", dispatch);
window.addEventListener("DOMContentLoaded", () => {
  if (!window.location.hash) window.location.hash = "#/";
  // Wave 32: wire up language switcher in the header.
  const sel = document.getElementById("lang-switcher");
  if (sel) {
    sel.value = currentLocale();
    sel.addEventListener("change", (e) => setLocale(e.target.value));
  }
  dispatch();
});

function showError(e) {
  console.error(e);
  $("#app").innerHTML = "";
  $("#app").appendChild(h("div", { class: "card" }, [
    h("h2", {}, "Error"),
    h("pre", { class: "muted" }, e.message || String(e)),
  ]));
  toast(e.message || String(e), "error");
}

function navigate(p) { window.location.hash = "#" + p; }

// ----- Crumbs / header ------------------------------------------------------
function setCrumbs(parts) {
  const c = $("#crumbs");
  c.innerHTML = "";
  parts.forEach((p, i) => {
    if (i > 0) c.appendChild(h("span", { class: "sep" }, "›"));
    if (p.href) c.appendChild(h("a", { href: "#" + p.href }, p.label));
    else c.appendChild(h("span", {}, p.label));
  });
}

function setMeta(text) { $("#topMeta").textContent = text || ""; }

// ============================================================================
// Dashboard
// ============================================================================
route(/^\/$/, async () => {
  setCrumbs([{ label: "Dashboard" }]);
  setMeta("");
  const cases = await api("GET", "/api/cases");
  const app = $("#app");
  app.innerHTML = "";

  // New-case form. Issue #19/#25: Timezone is a pulldown of IANA TZDB
  // values (defaults to the browser-detected zone), Language is a
  // pulldown of supported report languages (ja/en).
  const form = h("div", { class: "card" }, [
    h("h2", {}, "新規ケース作成"),
    formRow("case_id", "Case ID", "INC-2026-XXXX"),
    formRow("name", "Name", "Suspicious activity on host01"),
    formRow("examiner", "Examiner", "examiner-web"),
    formSelectRow("timezone", "Timezone", supportedTimezones(), detectDefaultTZ()),
    formSelectRow("language", "Language", SUPPORTED_LANGUAGES, "ja"),
    h("div", { class: "row" }, [
      h("button", {
        class: "primary",
        onclick: async () => {
          const body = {
            case_id: $("#f_case_id").value.trim(),
            name: $("#f_name").value.trim(),
            examiner: $("#f_examiner").value.trim() || "examiner-web",
            timezone: $("#f_timezone").value.trim() || "UTC",
            language: $("#f_language").value.trim() || "ja",
          };
          if (!body.case_id || !body.name) {
            toast("case_id and name are required", "error");
            return;
          }
          try {
            await api("POST", "/api/cases", body);
            toast("Case created: " + body.case_id, "success");
            dispatch();
          } catch (e) { toast(e.message, "error"); }
        },
      }, "Create case"),
    ]),
  ]);
  app.appendChild(form);

  // Case list
  const list = h("div", { class: "card" }, [
    h("div", { class: "row", style: "align-items: center;" }, [
      h("h2", { style: "flex: 1; margin: 0;" }, `ケース一覧 (${cases.length})`),
      // Issue #16: Import a .fcz exported from another environment.
      h("label", {
        class: "ghost",
        style: "display: inline-flex; gap: 6px; align-items: center; cursor: pointer; padding: 6px 12px; border-radius: 3px;",
        title: "Upload a .fcz case archive",
      }, [
        h("span", {}, "⤒ Import .fcz"),
        h("input", {
          type: "file", accept: ".fcz,.tar.gz,application/gzip",
          style: "display: none;",
          onchange: async (ev) => {
            const file = ev.target.files[0];
            if (!file) return;
            const fd = new FormData();
            fd.append("file", file);
            const overwrite = confirm(
              "Overwrite an existing case with the same case_id if present?"
            ) ? "true" : "false";
            try {
              const res = await fetch(
                `/api/cases/import?overwrite=${overwrite}`,
                { method: "POST", body: fd }
              );
              const body = await res.json();
              if (!res.ok) throw new Error(body.error || res.statusText);
              toast(`Imported ${body.case_id} (verified ${body.sha256_verified} files)`, "success");
              dispatch();
            } catch (e) { toast("Import failed: " + e.message, "error"); }
            ev.target.value = "";
          },
        }),
      ]),
    ]),
    h("div", { style: "height: 8px;" }),
  ]);
  if (cases.length === 0) {
    list.appendChild(h("div", { class: "empty" }, "No cases yet — create one above."));
  } else {
    const grid = h("div", { class: "cases-grid" });
    cases.forEach((c) => grid.appendChild(caseCard(c)));
    list.appendChild(grid);
  }
  app.appendChild(list);
});

function formRow(name, label, placeholder) {
  return h("div", { class: "form-row" }, [
    h("label", {}, label),
    h("input", { id: "f_" + name, placeholder, value: "" }),
  ]);
}

// IANA TZDB pulldown (Issue #19, #25). Uses Intl.supportedValuesOf when
// available (Chromium/Firefox/Safari 2022+) and falls back to a curated
// list of common zones so the form still works on older runtimes.
function supportedTimezones() {
  try {
    if (typeof Intl !== "undefined" &&
        typeof Intl.supportedValuesOf === "function") {
      const tz = Intl.supportedValuesOf("timeZone");
      if (Array.isArray(tz) && tz.length > 0) return tz;
    }
  } catch (_) {}
  return [
    "UTC",
    "Asia/Tokyo", "Asia/Seoul", "Asia/Shanghai", "Asia/Hong_Kong",
    "Asia/Taipei", "Asia/Singapore", "Asia/Bangkok", "Asia/Kolkata",
    "Asia/Dubai", "Asia/Jerusalem",
    "Europe/London", "Europe/Berlin", "Europe/Paris", "Europe/Madrid",
    "Europe/Moscow",
    "America/Los_Angeles", "America/Denver", "America/Chicago",
    "America/New_York", "America/Toronto", "America/Sao_Paulo",
    "Australia/Sydney", "Pacific/Auckland",
  ];
}

// Supported report/UI languages — keep in sync with renderer.go dictJA/dictEN.
const SUPPORTED_LANGUAGES = [
  { code: "ja", label: "日本語 (ja)" },
  { code: "en", label: "English (en)" },
];

function formSelectRow(name, label, options, defaultValue) {
  const sel = h("select", { id: "f_" + name });
  options.forEach((opt) => {
    const value = typeof opt === "string" ? opt : opt.code;
    const text  = typeof opt === "string" ? opt : opt.label;
    const o = h("option", { value }, text);
    if (value === defaultValue) o.selected = true;
    sel.appendChild(o);
  });
  return h("div", { class: "form-row" }, [h("label", {}, label), sel]);
}

function detectDefaultTZ() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch (_) { return "UTC"; }
}

function caseCard(c) {
  const badges = [];
  badges.push(h("span", { class: "badge ok" }, c.evidence_count + " evidence"));
  if (c.unified_event_rows > 0) badges.push(h("span", { class: "badge ok" }, c.unified_event_rows.toLocaleString() + " events"));
  if (c.has_findings) badges.push(h("span", { class: "badge ok" }, c.findings_count + " findings"));
  if (c.has_synthesis) badges.push(h("span", { class: "badge ok" }, "synth"));
  if (c.has_report) badges.push(h("span", { class: "badge ok" }, "report"));
  if (badges.length === 1) badges.push(h("span", { class: "badge pending" }, "no parse yet"));

  return h("div", {
    class: "case-card",
    onclick: () => navigate("/cases/" + encodeURIComponent(c.case_id)),
  }, [
    h("div", { class: "case-id" }, c.case_id),
    h("div", { class: "case-name" }, c.name),
    h("div", { class: "case-name muted" }, "Examiner: " + (c.examiner || "—") + " · " + (c.timezone || "UTC")),
    h("div", { class: "badges" }, badges),
  ]);
}

// ============================================================================
// Case detail
// ============================================================================
route(/^\/cases\/([^/]+)\/?$/, async ({ args, params }) => {
  const caseID = decodeURIComponent(args[0]);
  const tab = params.tab || "findings";
  setCrumbs([{ label: "Dashboard", href: "/" }, { label: caseID }]);

  const detail = await api("GET", `/api/cases/${encodeURIComponent(caseID)}`);
  setMeta(`evidence=${detail.case.evidence_count} events=${detail.case.unified_event_rows}`);

  const app = $("#app");
  app.innerHTML = "";

  // ---- header card
  const c = detail.case;
  const headerCard = h("div", { class: "card" }, [
    h("div", { class: "row", style: "align-items: center;" }, [
      h("div", { style: "flex: 1;" }, [
        h("h1", {}, c.case_id + " — " + c.name),
        h("div", { class: "muted" },
          `Examiner: ${c.examiner || "—"} · TZ: ${c.timezone || "UTC"} · Status: ${c.status || "active"} · Created: ${fmtTS(c.created_at)}`),
      ]),
      h("div", { class: "row", style: "gap: 8px;" }, [
        // Issue #16: Export this case as a .fcz tarball.
        h("button", {
          class: "ghost",
          title: "Download a .fcz containing case rows + workspace",
          onclick: async () => {
            const close = modal([
              h("h3", {}, "Export case " + caseID),
              h("p", { class: "muted" }, "Bundles the DuckDB rows (case + evidence + parse_results + unified_events) and the workspace tree (findings, reports, audit) into a single .fcz tarball with SHA-256 integrity."),
              h("label", { style: "display: flex; gap: 8px; align-items: center; margin: 8px 0;" }, [
                h("input", { type: "checkbox", id: "exp-include-ev" }),
                h("span", {}, "Include raw extractions/ subtree (can be many GiB)"),
              ]),
              h("div", { class: "actions" }, [
                h("button", { class: "ghost", onclick: () => close() }, "Cancel"),
                h("button", {
                  onclick: () => {
                    const inc = document.getElementById("exp-include-ev").checked ? "true" : "false";
                    // Trigger a real download by navigating an <a download>.
                    const a = document.createElement("a");
                    a.href = `/api/cases/${encodeURIComponent(caseID)}/export?include_evidence=${inc}`;
                    a.download = caseID + ".fcz";
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    close();
                    toast("Export download started", "success");
                  },
                }, "Download .fcz"),
              ]),
            ]);
          },
        }, "⤓ Export"),
        h("button", {
          class: "danger",
          onclick: async () => {
            const close = modal([
              h("h3", {}, "Delete case " + caseID + "?"),
              h("p", { class: "muted" }, "This removes the case from the index and deletes the workspace dir. Original evidence files are NOT touched."),
              h("div", { class: "actions" }, [
                h("button", { class: "ghost", onclick: () => close() }, "Cancel"),
                h("button", { class: "danger", onclick: async () => {
                  try { await api("DELETE", `/api/cases/${encodeURIComponent(caseID)}`);
                    close(); toast("Case deleted", "success"); navigate("/");
                  } catch (e) { toast(e.message, "error"); }
                }}, "Delete"),
              ]),
            ]);
          },
        }, "Delete case"),
      ]),
    ]),
  ]);
  app.appendChild(headerCard);

  // ---- pipeline buttons
  const pipeline = renderPipeline(caseID, detail);
  app.appendChild(pipeline);

  // ---- tabs (Wave 32: labels via t())
  const tabBar = h("div", { class: "tabs" });
  const tabs = [
    ["status",   t("tab.status")],
    ["events",   t("tab.events")],
    ["findings", t("tab.findings")],
    ["timeline", t("tab.timeline")],
    ["iocs",     t("tab.iocs")],
    ["mitre",    t("tab.mitre")],
    ["report",   t("tab.report")],
    ["audit",    t("tab.audit")],
  ];
  tabs.forEach(([id, label]) => {
    tabBar.appendChild(h("div", {
      class: "tab" + (id === tab ? " active" : ""),
      onclick: () => navigate(`/cases/${encodeURIComponent(caseID)}?tab=${id}`),
    }, label));
  });
  app.appendChild(tabBar);

  const tabPane = h("div", { id: "tabpane" });
  app.appendChild(tabPane);

  switch (tab) {
    case "status":     await renderStatus(tabPane, caseID); break;
    case "events":     await renderEvents(tabPane, caseID, detail); break;
    case "findings":   await renderFindings(tabPane, caseID); break;
    case "timeline":   await renderTimeline(tabPane, caseID); break;
    case "iocs":       await renderIOCs(tabPane, caseID); break;
    case "mitre":      await renderMITRE(tabPane, caseID); break;
    case "report":     await renderReport(tabPane, caseID); break;
    case "audit":      await renderAudit(tabPane, caseID); break;
    default:           tabPane.innerHTML = `<div class="empty">Unknown tab: ${escapeHTML(tab)}</div>`;
  }
});

// ----- pipeline buttons + status polling ------------------------------------
function renderPipeline(caseID, detail) {
  const wrap = h("div", { class: "pipeline" });

  // Wave 23: Auto-pilot — chain Parse → Analyze → Synthesize → Report with
  // both Review Gates set to auto-skip. Placed BEFORE the per-step buttons
  // so the examiner sees the "do it all" path first. Distinct primary
  // style + 🤖 emoji to differentiate from the 4 individual triggers.
  const autopilotBtn = h("button", {
    class: "primary",
    style: "margin-right: 12px;",
    title: "Run Parse → Analyze → Synthesize → Report end-to-end with both Review Gates auto-skipped. " +
           "All findings will be auto-approved. Use the individual buttons for examiner-supervised runs.",
    onclick: () => startAutopilot(caseID),
  }, t("btn.autopilot"));
  wrap.appendChild(autopilotBtn);

  const steps = [
    { kind: "parse",      label: t("btn.parse"),       handler: () => startParse(caseID) },
    { kind: "analyze",    label: t("btn.analyze"),     handler: () => startAnalyze(caseID) },
    { kind: "synthesize", label: t("btn.synthesize"),  handler: () => startSynthesize(caseID) },
    { kind: "report",     label: t("btn.report"),      handler: () => startReport(caseID) },
  ];
  // Issue #1: each step is wrapped in a .pipeline-step group so flex-wrap
  // breaks at step boundaries (button + progress + arrow stay together).
  // Without this, a long progress text could push the next step's button
  // off-screen with no wrap fallback.
  steps.forEach((s, i) => {
    const initial = (detail.jobs && detail.jobs[s.kind]) || { state: "idle" };
    const btn = h("button", { onclick: s.handler }, s.label);
    const block = buildProgressBlock(s.kind, initial);
    const stepDiv = h("div", { class: "pipeline-step" }, [
      btn,
      block,
      i < steps.length - 1 ? h("span", { class: "arrow" }, "→") : null,
    ]);
    wrap.appendChild(stepDiv);
  });
  // start polling
  pollPipeline(caseID, steps.map((s) => s.kind));
  return wrap;
}

// buildProgressBlock builds the per-step status block: a text label, a
// (conditionally-shown) progress bar, and ETA / counter / elapsed text.
function buildProgressBlock(kind, st) {
  const block = h("div", { class: "progress-block " + (st.state || "idle"),
                           id: "prog_" + kind });
  renderProgressBlock(block, st);
  return block;
}

function renderProgressBlock(block, st) {
  // Wave 15 fix: skip DOM rebuild when the state signature hasn't changed.
  // pollPipeline ticks every 2s for every step; without this guard the
  // entire block (innerHTML = "") gets wiped and rebuilt every tick even
  // for terminal states like succeeded/failed, which makes the status
  // text visibly flicker. Once a step is done the JSON the server returns
  // is byte-stable, so a signature match means we can no-op.
  const sig = JSON.stringify({
    state: st.state,
    progress: st.progress,
    message: st.message,
    error: st.error,
    current: st.current,
    total: st.total,
    elapsed: Math.round(st.elapsed_seconds || 0),
    eta: Math.round(st.eta_seconds || 0),
  });
  if (block.dataset.sig === sig) return;
  block.dataset.sig = sig;

  block.className = "progress-block " + (st.state || "idle");
  block.innerHTML = "";

  // Issue #2: the headline can be a long error like "FAIL · some tactics
  // failed: initial_access: claude-code call iter=1: claude CLI exec:..."
  // For non-failed states the CSS truncates with ellipsis (single line);
  // for failed states the CSS allows multi-line so the full text is
  // visible. The `title` attribute additionally surfaces full text in
  // a browser tooltip on hover for any state.
  const headLine = pipelineLabel(st);
  block.appendChild(h("div", {
    class: "progress-text",
    title: headLine,
  }, headLine));

  // Issue #8: cancel button while running. Tiny "✕" so it doesn't
  // dominate the layout. Confirms before sending to avoid accidental
  // cancels mid-Analyze (which throws away minutes of LLM cost).
  if (st.state === "running") {
    const caseID = st.case_id;
    const kind   = st.kind;
    const cancelBtn = h("button", {
      class: "ghost",
      style: "padding: 1px 8px; font-size: 10px; margin-top: 2px; align-self: flex-start;",
      title: "Cancel this step",
      onclick: async () => {
        if (!confirm(`Cancel ${kind}? Any partial output is kept on disk.`)) return;
        try {
          await api("POST", `/api/cases/${encodeURIComponent(caseID)}/${kind}/cancel`);
          toast(`${kind} cancellation sent`, "success");
        } catch (e) { toast(e.message, "error"); }
      },
    }, "✕ cancel");
    block.appendChild(cancelBtn);
  }

  if (st.state === "running" && st.total > 0) {
    const pct = Math.min(100, Math.round((st.current / st.total) * 100));
    const bar = h("div", { class: "progress-bar-track" },
      h("div", { class: "progress-bar-fill", style: `width: ${pct}%;` }));
    block.appendChild(bar);
    const meta = [];
    meta.push(`${st.current}/${st.total}  ${pct}%`);
    if (st.eta_seconds > 0) meta.push("ETA " + fmtDuration(st.eta_seconds));
    if (st.elapsed_seconds > 0) meta.push("elapsed " + fmtDuration(st.elapsed_seconds));
    block.appendChild(h("div", { class: "progress-meta" }, meta.join(" · ")));
  } else if (st.state === "running") {
    if (st.elapsed_seconds > 0) {
      block.appendChild(h("div", { class: "progress-meta" },
        "elapsed " + fmtDuration(st.elapsed_seconds)));
    }
  } else if (st.state === "succeeded") {
    if (st.elapsed_seconds > 0) {
      block.appendChild(h("div", { class: "progress-meta" },
        "took " + fmtDuration(st.elapsed_seconds)));
    }
  }
}

function fmtDuration(secs) {
  secs = Math.max(0, Math.round(secs));
  if (secs < 60) return secs + "s";
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  if (m < 60) return s ? `${m}m${s}s` : `${m}m`;
  const h = Math.floor(m / 60);
  const mm = m % 60;
  return mm ? `${h}h${mm}m` : `${h}h`;
}

function pipelineLabel(st) {
  if (!st || st.state === "idle") return "idle";
  if (st.state === "running") {
    return (st.progress ? `running · ${st.progress}` : "running");
  }
  if (st.state === "succeeded") return "ok · " + (st.message || "done");
  if (st.state === "failed")    return "FAIL · " + (st.error || "see logs");
  if (st.state === "canceled")  return "canceled · " + (st.message || "by examiner");
  return st.state;
}

const pipelinePolls = new Map();
function pollPipeline(caseID, kinds) {
  // Wave 16: clear EVERY existing poll before starting a new one. The
  // earlier code only cleared the entry for this exact caseID, so when
  // the examiner switched from case_3 to case_4, the case_3 poll kept
  // ticking in the background, fetching /api/cases/case_3/<kind>/status
  // every 2s and overwriting the new case's DOM elements (same `prog_*`
  // IDs). Result: case_3's error message ("case 'case_3' has no
  // registered evidence...") would appear next to case_4's Analyze All
  // button. We can't disambiguate which poll wrote what after the fact,
  // so the only correct policy is: at most one case is being viewed at
  // a time, therefore at most one poll set should be running.
  for (const intervalID of pipelinePolls.values()) {
    clearInterval(intervalID);
  }
  pipelinePolls.clear();
  const id = "pipeline:" + caseID;
  const tick = async () => {
    let anyRunning = false;
    for (const k of kinds) {
      try {
        const subpath = k === "synthesize" ? "synthesize" : k;
        const st = await api("GET", `/api/cases/${encodeURIComponent(caseID)}/${subpath}/status`);
        const el = document.getElementById("prog_" + k);
        if (el) renderProgressBlock(el, st);
        if (st.state === "running") anyRunning = true;
      } catch (_) {}
    }
    if (!anyRunning) {
      // slow poll when nothing running
    }
  };
  tick();
  pipelinePolls.set(id, setInterval(tick, 2000));
}

// startParse opens the multi-evidence Parse modal (★v0.3 #1).
// Each "row" is one evidence (path + optional id). + adds rows, − removes.
// Submitting POSTs evidences:[...] to the parse endpoint, which loops
// the orchestrator per evidence and only proceeds once all complete
// (graceful: per-evidence failures are logged but don't abort siblings).
async function startParse(caseID) {
  const rows = h("div", { id: "p_rows" });
  let rowSeq = 0;
  function addRow(path, evid) {
    const idx = rowSeq++;
    const row = h("div", {
      class: "form-row p_row",
      "data-row-idx": idx,
      style: "gap: 6px; align-items: center;",
    }, [
      h("input", {
        class: "p_path",
        placeholder: "/cases/<...>/triage.zip or /cases/<...>/evidence_dir",
        value: path || "",
        style: "flex: 3;",
      }),
      h("input", {
        class: "p_evid",
        placeholder: "EV-001 (auto)",
        value: evid || "",
        style: "flex: 1; max-width: 160px;",
      }),
      h("button", {
        class: "ghost",
        title: "remove this evidence",
        onclick: () => {
          if (rows.children.length > 1) row.remove();
          else toast("少なくとも 1 つの evidence が必要です", "error");
        },
      }, "−"),
    ]);
    rows.appendChild(row);
  }
  addRow();

  // Issue #23: input-type selector. Three modes:
  //  - image  : disk image (E01 / raw / VMDK / VHD / VHDX) — extractor
  //             stage runs first, downstream parsers walk the staging dir
  //  - cdir   : artifacts pre-organised in per-category folders (already
  //             handled by the existing **/glob detectors)
  //  - washizukami : Washizukami-Collector layout with collection.log
  //             (handled by washizukami_audit_parser + path-preserving globs)
  //  - auto   : let the orchestrator decide (default; magic-byte + glob)
  //
  // When "image" is selected a sub-select gates the format. "auto" inside
  // image lets image_extractor.py decide by magic bytes — most reliable.
  const imageFormatSelect = h("select", { id: "p_image_format", disabled: "disabled" }, [
    h("option", { value: "auto" }, "Auto-detect (magic bytes)"),
    h("option", { value: "ewf" },  "EWF (.E01 / .Ex01)"),
    h("option", { value: "raw" },  "raw (.dd / .img / .raw)"),
    h("option", { value: "vmdk" }, "VMDK (.vmdk)"),
    h("option", { value: "vhd" },  "VHD (.vhd)"),
    h("option", { value: "vhdx" }, "VHDX (.vhdx)"),
  ]);
  const inputModeSelect = h("select", {
    id: "p_input_mode",
    onchange: (ev) => {
      imageFormatSelect.disabled = ev.target.value !== "image";
    },
  }, [
    h("option", { value: "auto" }, "Auto-detect (recommended)"),
    h("option", { value: "image" }, "Image — Disk image (E01 / raw / VMDK / VHD / VHDX)"),
    h("option", { value: "cdir" },  "CDIR — Artifacts organised per category folder"),
    h("option", { value: "washizukami" }, "Washizukami-Collector — preserved directory tree"),
  ]);

  modal([
    h("h3", {}, "Run parser for " + caseID),
    h("p", { class: "muted", style: "margin-top: 0;" },
      "1 ケースに対して **複数の Evidence を一度に登録 + パース** できます。" +
      "各 evidence は順次 orchestrator にかけられ、1 つが失敗しても他は続行します(graceful degradation)。" +
      "全 evidence の完了後に Tier 1 (Analyze) を回せます。"),
    // Issue #23: input-type + image-format selectors
    h("div", { class: "form-row" }, [h("label", {}, "Input type"), inputModeSelect]),
    h("div", { class: "form-row" }, [h("label", {}, "Image format"), imageFormatSelect]),
    h("p", { class: "muted", style: "font-size: 11px; margin-top: -4px;" },
      "Image を選ぶと parser 開始時に画像をマウントし、$MFT/$J/registry/EVTX/Prefetch/Tasks/SRUM + per-user hive を Sleuth Kit で抽出してから通常パイプラインを走らせます (extract.log と Extracts セクションで確認可能)。CDIR / Washizukami はディレクトリ構造のヒントを保存しますが、既存の検出器が同じ glob で拾うため動作は Auto と等価です。"),
    h("div", { class: "form-row", style: "gap: 6px;" }, [
      h("label", { style: "flex: 3;" }, "Evidence path (.zip / dir / image)"),
      h("label", { style: "flex: 1; max-width: 160px;" }, "Evidence ID (optional)"),
      h("span", { style: "width: 32px;" }, ""),
    ]),
    rows,
    h("div", { style: "margin-top: 4px;" }, [
      h("button", { class: "ghost", onclick: () => addRow() }, "＋ Add evidence"),
    ]),
    // Issue #12: optional skip-Gate-0 toggle so the examiner can opt
    // out of parse-result review at the same time as kicking off Parse.
    // Setting auto_skip BEFORE Parse means newly-produced parse_results
    // won't block Analyze either.
    h("div", { class: "form-row", style: "margin-top: 12px;" }, [
      h("label", {}, "Review Gate 0 をスキップ"),
      h("input", {
        type: "checkbox", id: "p_skip_gate0",
        title: "ON にすると Parse 完了後のレビューを飛ばし、Analyze がブロックされなくなる (auto_skip)",
      }),
    ]),
    h("p", { class: "muted", style: "font-size: 11px; margin-top: 0;" },
      "★ ON: 全 parse 結果を auto-approve 扱いにする。" +
      "Events タブで個別レビューせずに即 Analyze に進みたいとき。"),
    h("div", { class: "actions" }, [
      (() => {
        const cancelBtn = h("button", { class: "ghost" }, "Cancel");
        cancelBtn.onclick = () => closeModal();
        return cancelBtn;
      })(),
      h("button", {
        class: "primary",
        onclick: async () => {
          const evidences = Array.from(rows.querySelectorAll(".p_row")).map((row) => ({
            evidence_path: row.querySelector(".p_path").value.trim(),
            evidence_id:   row.querySelector(".p_evid").value.trim(),
          })).filter((e) => e.evidence_path);
          if (evidences.length === 0) {
            toast("少なくとも 1 つの evidence_path が必要です", "error");
            return;
          }
          // Issue #23: input-type + image-format hints. "auto" sends nothing
          // (server keeps current behavior); explicit modes set a hint that
          // the server validates against the file before running the parser.
          const inputMode = $("#p_input_mode").value || "auto";
          const imageFormat = $("#p_image_format").value || "auto";
          try {
            // Set Gate 0 auto_skip first if requested — applies to the
            // parse results this run will produce (Issue #12).
            if ($("#p_skip_gate0").checked) {
              await api("POST",
                `/api/cases/${encodeURIComponent(caseID)}/parse-review/skip-all`,
                { auto_skip: true });
            }
            await api("POST", `/api/cases/${encodeURIComponent(caseID)}/parse`,
              { evidences, input_mode: inputMode, image_format: imageFormat });
            closeModal();
            toast(`Parse started (${evidences.length} evidence${evidences.length > 1 ? "s" : ""})`, "success");
          } catch (e) { toast(e.message, "error"); }
        },
      }, "Start parse"),
    ]),
  ]);
}

// Tiny helper because the original Cancel callback used the modal()
// return value; the new layout above can't capture it inline easily.
function closeModal() {
  const shade = $("#modal");
  if (shade) shade.classList.add("hidden");
}

async function startAnalyze(caseID) {
  // Pre-check LLM availability so we can warn upfront instead of failing
  // at iter=1 in every tactic. Best-effort — modal still opens on error.
  let llm = { ok: true, claude_cli: true, api_key_set: true, claude_version: "" };
  try { llm = await api("GET", "/api/health/llm"); } catch (_) {}
  const warn = !llm.ok ? h("div", {
    class: "card", style: "background:#3a1e1e; border-color:#e74c3c; padding:8px 12px; margin: 0 0 8px 0;",
  }, [
    h("strong", { style: "color:#e74c3c;" }, "⚠ LLM access not detected"),
    h("p", { class: "muted", style: "margin: 4px 0 0 0; font-size: 11px;" },
      "Neither the `claude` CLI nor the ANTHROPIC_API_KEY env var is " +
      "available. Analyze will fail at iter=1 for every tactic. " +
      "Either install Claude Code CLI (`npm i -g @anthropic-ai/claude-code` + " +
      "`claude` once to /login), or `export ANTHROPIC_API_KEY=...` and " +
      "restart the server."),
  ]) : null;
  const llmInfo = llm.ok ? h("p", { class: "muted", style: "font-size: 11px; margin-top: 0;" },
    "✓ LLM access OK — " +
    (llm.claude_cli ? `claude CLI (${llm.claude_version || "version unknown"})` : "") +
    (llm.claude_cli && llm.api_key_set ? " + " : "") +
    (llm.api_key_set ? "ANTHROPIC_API_KEY set" : "")) : null;

  const close = modal([
    h("h3", {}, "Run all 10 Tactic Agents"),
    warn,
    llmInfo,
    h("p", { class: "muted" },
      "Engine: claude-code (default). Set ANTHROPIC_API_KEY first if you choose anthropic-api."),
    h("div", { class: "form-row" }, [h("label", {}, "Engine"),
      h("select", { id: "a_engine" }, [
        h("option", { value: "claude-code" }, "claude-code"),
        h("option", { value: "anthropic-api" }, "anthropic-api"),
      ])]),
    h("div", { class: "form-row" }, [h("label", {}, "Model"),
      h("input", { id: "a_model", placeholder: "(engine default)" })]),
    h("div", { class: "form-row" }, [h("label", {}, "Include anomaly_hunter"),
      h("input", { id: "a_anomaly", type: "checkbox" })]),
    // Issue #11: surface the already-existing Gate 0 skip-all so the
    // examiner can opt out of parse-result review from this modal.
    h("div", { class: "form-row" }, [
      h("label", {}, "Review Gate 0 をスキップ"),
      h("input", {
        type: "checkbox", id: "a_skip_gate0",
        title: "ON にすると Parse Results の人間レビューを飛ばして Analyze を開始 (auto_skip)",
      }),
    ]),
    h("p", { class: "muted", style: "font-size: 11px; margin-top: 0;" },
      "★ ON: 全 parse 結果を auto-approve 扱い → Analyze をブロックしない。" +
      "OFF (デフォルト): Events タブで approve していない parse 結果があると Analyze は 409 で停止"),
    h("div", { class: "actions" }, [
      h("button", { class: "ghost", onclick: () => close() }, "Cancel"),
      h("button", { class: "primary", onclick: async () => {
        try {
          // If skip-Gate-0 is checked, flip auto_skip BEFORE kicking off
          // analyze so the gate check sees it.
          if ($("#a_skip_gate0").checked) {
            await api("POST",
              `/api/cases/${encodeURIComponent(caseID)}/parse-review/skip-all`,
              { auto_skip: true });
          }
          await api("POST", `/api/cases/${encodeURIComponent(caseID)}/analyze`, {
            engine: $("#a_engine").value,
            model:  $("#a_model").value.trim(),
            include_anomaly: $("#a_anomaly").checked,
          });
          close(); toast("Analyze started", "success");
        } catch (e) { toast(e.message, "error"); }
      }}, "Start analyze"),
    ]),
  ]);
}

async function startSynthesize(caseID) {
  const close = modal([
    h("h3", {}, "Run Synthesizer"),
    h("div", { class: "form-row" }, [h("label", {}, "Run Corrector"),
      h("input", { id: "s_correct", type: "checkbox" })]),
    h("p", { class: "muted" }, "Without Corrector this is purely deterministic; with it, Tactic Agents may be re-run for inconsistency rules."),
    h("div", { class: "actions" }, [
      h("button", { class: "ghost", onclick: () => close() }, "Cancel"),
      h("button", { class: "primary", onclick: async () => {
        try {
          await api("POST", `/api/cases/${encodeURIComponent(caseID)}/synthesize`, {
            correct: $("#s_correct").checked,
          });
          close(); toast("Synthesis started", "success");
        } catch (e) { toast(e.message, "error"); }
      }}, "Start synthesize"),
    ]),
  ]);
}

async function startReport(caseID) {
  const close = modal([
    h("h3", {}, "Generate report"),
    h("div", { class: "form-row" }, [h("label", {}, "Language"),
      h("select", { id: "r_lang" }, [
        h("option", { value: "ja" }, "日本語"),
        h("option", { value: "en" }, "English"),
      ])]),
    h("div", { class: "form-row" }, [h("label", {}, "Only approved"),
      h("input", { id: "r_approved", type: "checkbox" })]),
    h("div", { class: "actions" }, [
      h("button", { class: "ghost", onclick: () => close() }, "Cancel"),
      h("button", { class: "primary", onclick: async () => {
        try {
          await api("POST", `/api/cases/${encodeURIComponent(caseID)}/report`, {
            language: $("#r_lang").value,
            only_approved: $("#r_approved").checked,
          });
          close(); toast("Report generation started", "success");
        } catch (e) { toast(e.message, "error"); }
      }}, "Generate"),
    ]),
  ]);
}

// ============================================================================
// Wave 23 Auto-pilot — Parse → Analyze → Synthesize → Report end-to-end with
// both Review Gates auto-skipped. Pure client-side orchestration: no new
// backend endpoint; reuses /parse-review/skip-all + /timeline-review/skip-all
// to silence the gates, then chains the existing per-step POSTs and polls
// each /status endpoint until it reaches "succeeded" (or "failed" → abort).
//
// Trade-off: if the user closes the browser mid-chain, the currently-running
// phase keeps going server-side (jobs.go owns its own goroutine) but the
// chain is broken — subsequent phases need to be triggered manually. For
// hackathon-scale runs (1-2h end-to-end) this is acceptable. A future
// server-side Auto-pilot endpoint would survive client disconnects.
// ============================================================================

async function startAutopilot(caseID) {
  const close = modal([
    h("h3", {}, "🤖 Auto-pilot — Parse → Analyze → Synthesize → Report"),
    h("p", { class: "muted", style: "font-size: 12px;" },
      "Both Review Gates (0: parse results, 2: timeline) will be auto-skipped. " +
      "All findings will reach the final report without per-item human approval. " +
      "Use the individual buttons above for examiner-supervised runs."),
    h("div", { class: "form-row" }, [
      h("label", {}, "Evidence path"),
      h("input", { id: "ap_path",
                   placeholder: "/cases/<...>/triage.zip or /cases/<...>/evidence.E01",
                   style: "flex: 3;" }),
    ]),
    h("div", { class: "form-row" }, [
      h("label", {}, "Input mode"),
      h("select", { id: "ap_input_mode" }, [
        h("option", { value: "auto" }, "auto"),
        h("option", { value: "cdir" }, "cdir"),
        h("option", { value: "image" }, "image"),
        h("option", { value: "washizukami" }, "washizukami"),
      ]),
    ]),
    h("div", { class: "form-row" }, [
      h("label", {}, "Report language"),
      h("select", { id: "ap_lang" }, [
        h("option", { value: "ja" }, "日本語"),
        h("option", { value: "en" }, "English"),
      ]),
    ]),
    h("div", { class: "actions" }, [
      h("button", { class: "ghost", onclick: () => close() }, "Cancel"),
      h("button", { class: "primary", onclick: async () => {
        const path = $("#ap_path").value.trim();
        if (!path) { toast("evidence path is required", "error"); return; }
        const inputMode = $("#ap_input_mode").value || "auto";
        const lang = $("#ap_lang").value || "ja";
        close();
        toast("🤖 Auto-pilot: skipping gates and starting parse…", "success");
        try {
          await api("POST",
            `/api/cases/${encodeURIComponent(caseID)}/parse-review/skip-all`,
            { auto_skip: true });
          await api("POST",
            `/api/cases/${encodeURIComponent(caseID)}/timeline-review/skip-all`,
            { auto_skip: true });
          await api("POST",
            `/api/cases/${encodeURIComponent(caseID)}/parse`,
            { evidences: [{ evidence_path: path }], input_mode: inputMode });
          // Fire-and-forget chain runner (errors surface via toasts).
          autopilotChain(caseID, lang);
        } catch (e) {
          toast("Auto-pilot start failed: " + e.message, "error");
        }
      }}, "Start Auto-pilot"),
    ]),
  ]);
}

async function autopilotChain(caseID, lang) {
  try {
    await waitForJob(caseID, "parse");
    toast("Auto-pilot: parse ✓ — starting analyze…", "success");
    await api("POST",
      `/api/cases/${encodeURIComponent(caseID)}/analyze?force=true`,
      {});
    await waitForJob(caseID, "analyze");
    toast("Auto-pilot: analyze ✓ — starting synthesize…", "success");
    await api("POST",
      `/api/cases/${encodeURIComponent(caseID)}/synthesize`,
      { correct: false });
    await waitForJob(caseID, "synthesize");
    toast("Auto-pilot: synthesize ✓ — starting report…", "success");
    await api("POST",
      `/api/cases/${encodeURIComponent(caseID)}/report?force=true`,
      { language: lang });
    await waitForJob(caseID, "report");
    toast("✅ Auto-pilot complete — open Report tab", "success");
  } catch (e) {
    toast("🤖 Auto-pilot aborted: " + e.message, "error");
  }
}

async function waitForJob(caseID, kind) {
  // Polls the /<kind>/status endpoint every 3 s until state ∈
  // {succeeded, failed, canceled}. Throws on failed/canceled so the
  // chain aborts immediately.
  while (true) {
    await new Promise((r) => setTimeout(r, 3000));
    let st;
    try {
      st = await api("GET", `/api/cases/${encodeURIComponent(caseID)}/${kind}/status`);
    } catch (e) {
      throw new Error(`${kind} status fetch failed: ${e.message}`);
    }
    if (st.state === "succeeded") return st;
    if (st.state === "failed")   throw new Error(`${kind} failed: ${st.error || st.message || "(no detail)"}`);
    if (st.state === "canceled") throw new Error(`${kind} canceled by examiner`);
    // idle is fine briefly right after POST; running is the expected hot state.
  }
}

// ============================================================================
// Findings tab
// ============================================================================
// findingsView is the per-tab state shared across actions. Stored on the
// pane element so navigating away + back rebuilds it cleanly.
//
// Issues addressed:
//   #4  filter (all / pending / reviewed) — toggle in toolbar
//   #5  bulk select + no-scroll-jump — checkboxes + bulk toolbar; surgical
//       row updates instead of full re-render
//   #6  default collapsed tactic groups
//   #7  reset (un-review) action available even after approve/reject
//   #10 "Approve all visible" button (respects filter)
async function renderFindings(pane, caseID) {
  pane.innerHTML = `<div class="empty"><span class="spinner"></span>loading findings…</div>`;
  let findings;
  try { findings = await api("GET", `/api/cases/${encodeURIComponent(caseID)}/findings`); }
  catch (e) { pane.innerHTML = `<div class="empty">No findings yet (run Analyze first).</div>`; return; }
  if (!findings || findings.length === 0) {
    pane.innerHTML = `<div class="empty">No findings yet (run Analyze first).</div>`; return;
  }

  // Group by tactic
  const groups = new Map();
  for (const f of findings) {
    const k = f.tactic;
    if (!groups.has(k)) groups.set(k, { id: f.tactic_id, name: f.tactic_name, findings: [] });
    groups.get(k).findings.push(f);
  }

  // Per-tab state container — every action mutates this and updates the
  // affected DOM nodes in place (Issue #5: no full re-render so the
  // viewport doesn't jump back to the top).
  pane._findings = {
    caseID,
    findingsById: Object.fromEntries(findings.map((f) => [f.finding_id, f])),
    selected: new Set(),     // finding_ids the user has ticked
    filter: "all",           // all | pending | reviewed
  };

  pane.innerHTML = "";

  // ── Toolbar (filter + bulk actions + summary) ──
  const toolbar = h("div", { class: "findings-toolbar" });
  pane.appendChild(toolbar);
  refreshFindingsToolbar(pane);

  // ── Tactic groups ──
  for (const [slug, g] of [...groups.entries()].sort((a, b) => a[1].id.localeCompare(b[1].id))) {
    const list = h("div", { class: "findings hidden" }); // Issue #6: collapsed by default
    const header = h("div", { class: "tactic-header" }, [
      h("span", { class: "tactic-toggle" }, "▸"),
      h("span", { class: "name" }, g.name || slug),
      h("span", { class: "muted" }, "(" + g.id + ")"),
      h("span", { class: "spacer" }),
      h("span", { class: "count" }, g.findings.length + " findings"),
    ]);
    header.onclick = (ev) => {
      // ignore clicks on the "select-all" checkbox (added below)
      if (ev.target.tagName === "INPUT") return;
      const collapsed = list.classList.toggle("hidden");
      header.querySelector(".tactic-toggle").textContent = collapsed ? "▸" : "▾";
    };
    // Per-tactic select-all checkbox (Issue #5)
    const groupCheck = h("input", {
      type: "checkbox",
      class: "tactic-select-all",
      title: "select all in this tactic",
      onclick: (ev) => {
        ev.stopPropagation();
        const checked = ev.target.checked;
        for (const f of g.findings) {
          if (!findingMatchesFilter(f, pane._findings.filter)) continue;
          if (checked) pane._findings.selected.add(f.finding_id);
          else pane._findings.selected.delete(f.finding_id);
          const cb = pane.querySelector(`input.row-select[data-fid="${cssEscape(f.finding_id)}"]`);
          if (cb) cb.checked = checked;
        }
        refreshFindingsToolbar(pane);
      },
    });
    header.insertBefore(groupCheck, header.firstChild);

    g.findings.forEach((f) => list.appendChild(findingRow(caseID, f, pane)));

    const group = h("div", { class: "tactic-group" }, [header, list]);
    pane.appendChild(group);
  }
}

function findingMatchesFilter(f, mode) {
  if (mode === "pending")  return !f.approved && !f.rejected;
  if (mode === "reviewed") return f.approved || f.rejected;
  return true; // "all"
}

function refreshFindingsToolbar(pane) {
  const state = pane._findings;
  const findings = Object.values(state.findingsById);
  const total = findings.length;
  const approved = findings.filter((f) => f.approved).length;
  const rejected = findings.filter((f) => f.rejected).length;
  const pending = total - approved - rejected;
  const selectedCount = state.selected.size;
  const visibleCount = findings.filter((f) => findingMatchesFilter(f, state.filter)).length;

  const toolbar = pane.querySelector(".findings-toolbar");
  toolbar.innerHTML = "";

  // Filter (Issue #4)
  const filterRow = h("div", { class: "row", style: "gap: 6px; align-items: center;" }, [
    h("span", { class: "muted", style: "font-size: 11px;" }, "Filter:"),
    ...["all","pending","reviewed"].map((mode) => {
      const btn = h("button", {
        class: state.filter === mode ? "primary" : "ghost",
        style: "padding: 4px 10px; font-size: 11px;",
        onclick: () => {
          state.filter = mode;
          // Apply CSS class to hide non-matching rows; no DOM rebuild.
          for (const f of findings) {
            const row = pane.querySelector(`.finding[data-fid="${cssEscape(f.finding_id)}"]`);
            if (!row) continue;
            row.classList.toggle("filtered-out", !findingMatchesFilter(f, mode));
          }
          refreshFindingsToolbar(pane);
        },
      }, mode);
      return btn;
    }),
    h("span", { class: "spacer" }),
    h("span", { class: "muted", style: "font-size: 11px;" },
      `Total ${total} · approved ${approved} · rejected ${rejected} · pending ${pending}` +
      (state.filter !== "all" ? ` · showing ${visibleCount}` : "")),
  ]);
  toolbar.appendChild(filterRow);

  // Bulk action row (Issue #5 + #10) — only shown when ≥1 selected, or
  // always with the "approve all visible" button.
  const bulkRow = h("div", { class: "row", style: "gap: 6px; align-items: center; margin-top: 6px;" }, [
    h("span", { class: "muted", style: "font-size: 11px;" },
      selectedCount > 0 ? `${selectedCount} selected` : "(no rows selected)"),
    h("button", {
      style: "padding: 4px 10px; font-size: 11px;",
      disabled: selectedCount === 0 ? "disabled" : null,
      onclick: () => bulkAction(pane, "approve"),
    }, "Approve selected"),
    h("button", {
      class: "danger",
      style: "padding: 4px 10px; font-size: 11px;",
      disabled: selectedCount === 0 ? "disabled" : null,
      onclick: () => bulkActionWithReason(pane, "reject"),
    }, "Reject selected…"),
    h("button", {
      class: "ghost",
      style: "padding: 4px 10px; font-size: 11px;",
      disabled: selectedCount === 0 ? "disabled" : null,
      onclick: () => bulkAction(pane, "reset"),
    }, "Reset selected"),
    h("span", { class: "spacer" }),
    // Issue #10: "Approve all visible" — respects current filter
    h("button", {
      class: "primary",
      style: "padding: 4px 10px; font-size: 11px;",
      title: "Approve every finding currently visible (respects the filter above)",
      disabled: visibleCount === 0 ? "disabled" : null,
      onclick: async () => {
        if (!confirm(`Approve all ${visibleCount} visible finding(s)?`)) return;
        const ids = findings
          .filter((f) => findingMatchesFilter(f, state.filter))
          .map((f) => f.finding_id);
        await runBulk(pane, ids, "approve", "");
      },
    }, `Approve all visible (${visibleCount})`),
  ]);
  toolbar.appendChild(bulkRow);
}

async function bulkAction(pane, action) {
  const ids = [...pane._findings.selected];
  if (ids.length === 0) return;
  if (action === "approve" && !confirm(`Approve ${ids.length} finding(s)?`)) return;
  if (action === "reset"   && !confirm(`Reset ${ids.length} finding(s) to pending?`)) return;
  await runBulk(pane, ids, action, "");
}

async function bulkActionWithReason(pane, action) {
  const ids = [...pane._findings.selected];
  if (ids.length === 0) return;
  let reason = null;
  const close = modal([
    h("h3", {}, `Reject ${ids.length} finding(s)`),
    h("div", { class: "form-row" }, [h("label", {}, "Reason (optional)"),
      h("input", { id: "bulk_reason", placeholder: "why are these not true positives? (optional)" })]),
    h("div", { class: "actions" }, [
      h("button", { class: "ghost", onclick: () => closeModal() }, "Cancel"),
      h("button", { class: "danger", onclick: async () => {
        reason = $("#bulk_reason").value.trim();
        closeModal();
        await runBulk(pane, ids, action, reason);
      }}, "Reject all"),
    ]),
  ]);
}

async function runBulk(pane, ids, action, reason) {
  const state = pane._findings;
  try {
    const res = await api("POST",
      `/api/cases/${encodeURIComponent(state.caseID)}/findings/bulk`,
      { finding_ids: ids, action, reason });
    toast(`${action}: ${res.updated} updated` +
          (res.not_found && res.not_found.length ? `, ${res.not_found.length} not found` : ""),
          "success");
    // Update local state + DOM rows in place — no scroll jump (Issue #5)
    const now = new Date().toISOString();
    for (const id of ids) {
      const f = state.findingsById[id];
      if (!f) continue;
      if (action === "approve") {
        f.approved = true; f.rejected = false; f.reject_reason = "";
        f.reviewed_at = now; f.reviewed_by = "examiner-web";
      } else if (action === "reject") {
        f.approved = false; f.rejected = true; f.reject_reason = reason;
        f.reviewed_at = now; f.reviewed_by = "examiner-web";
      } else if (action === "reset") {
        f.approved = false; f.rejected = false; f.reject_reason = "";
        f.reviewed_at = ""; f.reviewed_by = "";
      }
      updateFindingRowDOM(pane, f);
      state.selected.delete(id);
    }
    // Uncheck the row checkboxes
    for (const id of ids) {
      const cb = pane.querySelector(`input.row-select[data-fid="${cssEscape(id)}"]`);
      if (cb) cb.checked = false;
    }
    refreshFindingsToolbar(pane);
  } catch (e) {
    toast(e.message, "error");
  }
}

// updateFindingRowDOM mutates the existing row element to reflect new
// review state — used after a single or bulk action so the viewport
// doesn't reset (Issue #5).
function updateFindingRowDOM(pane, f) {
  const row = pane.querySelector(`.finding[data-fid="${cssEscape(f.finding_id)}"]`);
  if (!row) return;
  row.className = "finding" + (f.approved ? " approved" : f.rejected ? " rejected" : "")
                + (findingMatchesFilter(f, pane._findings.filter) ? "" : " filtered-out");
  // Replace the state badge in the header
  const stateBadge = row.querySelector(".state-badge");
  if (stateBadge) {
    stateBadge.className = "badge state-badge "
      + (f.approved ? "approved" : f.rejected ? "rejected" : "pending");
    stateBadge.textContent = f.approved ? "approved" : f.rejected ? "rejected" : "pending";
  }
  // Replace the actions block
  const actions = row.querySelector(".actions");
  if (actions) {
    actions.innerHTML = "";
    rebuildActionButtons(pane, f, actions);
  }
}

function rebuildActionButtons(pane, f, actions) {
  const caseID = pane._findings.caseID;
  if (!f.approved && !f.rejected) {
    // Pending — show approve / reject (single-row buttons still work,
    // but the bulk toolbar is the encouraged path for many at once).
    actions.appendChild(h("button", {
      onclick: () => runBulk(pane, [f.finding_id], "approve", ""),
    }, "Approve"));
    actions.appendChild(h("button", {
      class: "danger",
      onclick: () => {
        modal([
          h("h3", {}, "Reject finding " + f.finding_id),
          h("div", { class: "form-row" }, [h("label", {}, "Reason (optional)"),
            h("input", { id: "rej_reason", placeholder: "why is this not a true positive? (optional)" })]),
          h("div", { class: "actions" }, [
            h("button", { class: "ghost", onclick: () => closeModal() }, "Cancel"),
            h("button", { class: "danger", onclick: () => {
              const reason = $("#rej_reason").value.trim();
              closeModal();
              runBulk(pane, [f.finding_id], "reject", reason);
            }}, "Reject"),
          ]),
        ]);
      },
    }, "Reject"));
  } else {
    // Reviewed — show "by X at Y" + reset button (Issue #7)
    actions.appendChild(h("span", { class: "muted" },
      "Reviewed by " + (f.reviewed_by || "?") + " · " + fmtTS(f.reviewed_at) +
      (f.reject_reason ? " · reason: " + f.reject_reason : "")));
    actions.appendChild(h("button", {
      class: "ghost",
      style: "margin-left: 8px;",
      title: "clear approve/reject and return to pending",
      onclick: () => runBulk(pane, [f.finding_id], "reset", ""),
    }, "Reset"));
  }
}

function findingRow(caseID, f, pane) {
  const row = h("div", {
    class: "finding" + (f.approved ? " approved" : f.rejected ? " rejected" : ""),
    "data-fid": f.finding_id,
  });
  const conf = (f.confidence || "low").toLowerCase();

  // Header: row checkbox (Issue #5) + confidence badge + technique + state badge
  const headerLine = h("div", { class: "header" }, [
    h("input", {
      type: "checkbox",
      class: "row-select",
      "data-fid": f.finding_id,
      onclick: (ev) => {
        if (ev.target.checked) pane._findings.selected.add(f.finding_id);
        else pane._findings.selected.delete(f.finding_id);
        refreshFindingsToolbar(pane);
      },
    }),
    h("span", { class: "badge " + conf }, conf),
    h("span", { class: "technique-id" }, f.technique_id || "?"),
    h("span", { class: "technique-name" }, f.technique_name || ""),
    h("span", { class: "spacer" }),
    h("span", { class: "muted" }, f.finding_id),
    h("span", {
      class: "badge state-badge " + (f.approved ? "approved" : f.rejected ? "rejected" : "pending"),
    }, f.approved ? "approved" : f.rejected ? "rejected" : "pending"),
  ]);
  row.appendChild(headerLine);
  row.appendChild(h("div", { class: "summary" }, f.summary || ""));
  if (f.reasoning) row.appendChild(h("div", { class: "reasoning" }, f.reasoning));

  // evidence list (collapsed by default). Issue #20: when expanded each row
  // must show the underlying event's timestamp + full payload (fetched by
  // audit_id once when the list is first opened — cached afterwards).
  const evList = h("div", { class: "evidence-list hidden" });
  const evItems = [];
  (f.evidence || []).forEach((ev) => {
    const item = h("div", { class: "evidence-item" });
    item.appendChild(h("div", { class: "evidence-head" }, [
      h("span", { class: "source" }, (ev.source_artifact || "?") + " "),
      h("span", { class: "audit-id" }, ev.audit_id),
    ]));
    if (ev.excerpt) item.appendChild(h("div", { class: "excerpt" }, ev.excerpt));
    const meta = h("div", { class: "evidence-meta muted" }, "");
    const payloadBox = h("pre", { class: "payload-pre evidence-payload" }, "");
    item.appendChild(meta);
    item.appendChild(payloadBox);
    evList.appendChild(item);
    evItems.push({ ev, meta, payloadBox });
  });
  let evLoaded = false;
  async function loadEvidencePayloads() {
    if (evLoaded) return;
    evLoaded = true;
    await Promise.all(evItems.map(async ({ ev, meta, payloadBox }) => {
      meta.textContent = "loading event…";
      try {
        const res = await api("GET",
          `/api/cases/${encodeURIComponent(caseID)}/events?audit_id=${encodeURIComponent(ev.audit_id)}&limit=1`);
        const row = (res.events || [])[0];
        if (!row) {
          meta.textContent = "no event found for audit_id " + ev.audit_id;
          payloadBox.textContent = "";
          return;
        }
        meta.textContent =
          `time: ${row.ts_utc || "?"} · event_type: ${row.event_type || "?"}` +
          (row.computer ? ` · computer: ${row.computer}` : "") +
          (row.evidence_id ? ` · evidence: ${row.evidence_id}` : "");
        let pretty = row.payload_json || "";
        try { pretty = JSON.stringify(JSON.parse(row.payload_json), null, 2); } catch (_) {}
        payloadBox.textContent = pretty;
      } catch (e) {
        meta.textContent = "load failed: " + e.message;
      }
    }));
  }
  const toggle = h("div", { class: "evidence-toggle" }, `▸ ${(f.evidence || []).length} evidence rows`);
  toggle.onclick = () => {
    const willOpen = evList.classList.contains("hidden");
    evList.classList.toggle("hidden");
    toggle.textContent = (willOpen ? "▾ " : "▸ ") +
                         (f.evidence || []).length + " evidence rows";
    if (willOpen) loadEvidencePayloads();
  };
  row.appendChild(toggle);
  row.appendChild(evList);

  // actions
  const actions = h("div", { class: "actions" });
  rebuildActionButtons(pane, f, actions);
  row.appendChild(actions);
  return row;
}

// cssEscape replaces characters that have meaning in CSS attribute
// selectors — finding_ids contain hyphens and digits, but we defensively
// escape anything non-word so future ID schemes don't break the
// querySelector calls.
function cssEscape(s) {
  return String(s).replace(/[^a-zA-Z0-9_-]/g, (c) => "\\" + c);
}

// ============================================================================
// Timeline tab
// ============================================================================
async function renderTimeline(pane, caseID) {
  pane.innerHTML = `<div class="empty"><span class="spinner"></span>loading timeline…</div>`;
  let data;
  try { data = await api("GET", `/api/cases/${encodeURIComponent(caseID)}/timeline`); }
  catch (e) { pane.innerHTML = `<div class="empty">No synthesis yet (run Synthesize first).</div>`; return; }

  // Wave 21: Review Gate 2 state (per-entry approve/reject). Fetch lazily —
  // if the endpoint fails (older server) the table renders without controls.
  let review = { auto_skip: false, reviews: {}, counts: {} };
  try {
    review = await api("GET", `/api/cases/${encodeURIComponent(caseID)}/timeline-review`);
  } catch (_) { /* old server; render without gate */ }

  pane.innerHTML = "";

  // Kill chain diagram
  const kc = h("div", { class: "killchain" });
  if (data.intrusion_path && data.intrusion_path.length > 0) {
    data.intrusion_path.forEach((s) => {
      kc.appendChild(h("div", { class: "step" }, [
        h("div", { class: "num" }, "STEP " + s.step),
        h("div", { class: "tactic" }, (s.tactic || "?") + " " + (s.tactic_name || "")),
        h("div", { class: "ts" }, fmtTS(s.timestamp)),
      ]));
    });
  } else {
    kc.appendChild(h("div", { class: "muted" }, "(no intrusion path inferred)"));
  }
  pane.appendChild(h("div", {}, [h("h3", {}, "Kill Chain"), kc]));

  // Wave 27: cross-evidence correlations panel. Only renders when the
  // synthesizer detected ≥1 technique observed across multiple evidences
  // (single-host cases get an empty list and we skip the section).
  const xev = data.cross_evidence_correlations || [];
  if (xev.length > 0) {
    const xevBox = h("div", { class: "cross-evidence-panel" });
    xevBox.appendChild(h("h3", {}, `Cross-evidence Correlations (${xev.length})`));
    xevBox.appendChild(h("p", { class: "muted", style: "font-size: 11px;" },
      "同じ MITRE technique が複数 evidence で観測されたケース。" +
      "warning = high-impact tactic (IA/CA/LM/DE/C2/Impact)、info = その他。"));
    const xtab = h("table", { class: "timeline-table" }, [
      h("thead", {}, h("tr", {}, [
        h("th", {}, "Severity"),
        h("th", {}, "Tactic"),
        h("th", {}, "Technique"),
        h("th", {}, "Evidences"),
        h("th", {}, "Description"),
      ])),
    ]);
    const xbody = h("tbody");
    xev.forEach((c) => {
      const sevBadge = h("span",
        { class: "badge " + (c.severity === "warning" ? "err" : "warn") },
        c.severity || "info");
      xbody.appendChild(h("tr", {}, [
        h("td", {}, sevBadge),
        h("td", {}, h("span", { class: "badge tactic" }, c.tactic || "")),
        h("td", {}, (c.technique_id || "") + (c.technique_name ? " · " + c.technique_name : "")),
        h("td", { class: "muted", style: "font-size: 11px;" },
          (c.evidence_ids || []).join(", ")),
        h("td", { class: "summary" }, c.description || ""),
      ]));
    });
    xtab.appendChild(xbody);
    xevBox.appendChild(xtab);
    pane.appendChild(xevBox);
  }

  // Wave 21: Review Gate 2 banner — roll-up + skip-all toggle.
  const c = review.counts || {};
  const totalRev = review.total || (data.timeline || []).length;
  const banner = h("div", { class: "row", style: "align-items: center; margin: 8px 0 6px; gap: 12px;" }, [
    h("span", { class: "muted" },
      `Review Gate 2: ${totalRev} entries · approved=${c.approved||0} · pending=${c.pending||0} · ` +
      `rejected=${c.rejected||0} · skipped=${c.skipped||0}`),
    h("span", { class: "spacer" }),
    h("label", { style: "display: flex; gap: 6px; align-items: center; font-size: 11px; cursor: pointer;" }, [
      h("input", {
        type: "checkbox", id: "gate2-skip-all",
        ...(review.auto_skip ? { checked: "checked" } : {}),
        onchange: async (ev) => {
          try {
            await api("POST", `/api/cases/${encodeURIComponent(caseID)}/timeline-review/skip-all`,
              { auto_skip: ev.target.checked });
            toast(ev.target.checked ? "Gate 2 skipped (all)" : "Gate 2 re-enabled", "success");
            await renderTimeline(pane, caseID);
          } catch (e) { toast(e.message, "error"); }
        },
      }),
      "Skip Review Gate 2 (auto-approve all)",
    ]),
  ]);
  pane.appendChild(banner);

  // Timeline table (Wave 21: + Review + Action columns)
  const table = h("table", { class: "timeline-table" }, [
    h("thead", {}, h("tr", {}, [
      h("th", {}, "Timestamp"),
      h("th", {}, "Tactic"),
      h("th", {}, "Technique"),
      h("th", {}, "Computer"),
      h("th", {}, "Summary"),
      h("th", {}, "Review"),
      h("th", {}, "Action"),
    ])),
  ]);
  const body = h("tbody");
  (data.timeline || []).forEach((t) => {
    const aid = t.audit_id || "";
    const rev = (review.reviews && review.reviews[aid]) || { state: "pending" };
    const stateClass = {
      approved: "approved", rejected: "rejected",
      skipped:  "pending",  pending:  "pending",
    }[rev.state] || "pending";
    const stateBadge = h("span", { class: "badge " + stateClass, title: rev.reason || "" }, rev.state || "pending");

    const action = h("div", { class: "row", style: "gap: 4px;" });
    if (!aid) {
      action.appendChild(h("span", { class: "muted", style: "font-size: 10px;" }, "(no audit_id)"));
    } else if (rev.state === "approved" || rev.state === "rejected") {
      action.appendChild(h("span", { class: "muted", style: "font-size: 10px;" },
        (rev.reviewed_by || "?") + " · " + fmtTS(rev.reviewed_at).slice(0, 16)));
    } else {
      action.appendChild(h("button", {
        style: "padding: 1px 8px; font-size: 10px;",
        onclick: async () => {
          try {
            await api("POST", `/api/cases/${encodeURIComponent(caseID)}/timeline-review/${encodeURIComponent(aid)}/approve`);
            toast("Approved " + aid.slice(0, 8), "success");
            await renderTimeline(pane, caseID);
          } catch (e) { toast(e.message, "error"); }
        },
      }, "Approve"));
      action.appendChild(h("button", {
        class: "danger",
        style: "padding: 1px 8px; font-size: 10px;",
        onclick: () => {
          const close = modal([
            h("h3", {}, "Reject timeline entry"),
            h("div", { class: "muted", style: "font-size: 11px; margin-bottom: 8px;" }, aid.slice(0, 16) + " · " + (t.summary || "").slice(0, 100)),
            h("div", { class: "form-row" }, [h("label", {}, "Reason"),
              h("input", { id: "tl_reason", placeholder: "why is this entry not relevant?" })]),
            h("div", { class: "actions" }, [
              h("button", { class: "ghost", onclick: () => close() }, "Cancel"),
              h("button", { class: "danger", onclick: async () => {
                try {
                  await api("POST", `/api/cases/${encodeURIComponent(caseID)}/timeline-review/${encodeURIComponent(aid)}/reject`,
                    { reason: $("#tl_reason").value.trim() });
                  close(); toast("Rejected " + aid.slice(0, 8), "success");
                  await renderTimeline(pane, caseID);
                } catch (e) { toast(e.message, "error"); }
              }}, "Reject"),
            ]),
          ]);
        },
      }, "Reject"));
    }

    body.appendChild(h("tr", { class: "timeline-row " + stateClass }, [
      h("td", { class: "ts" }, fmtTS(t.timestamp)),
      h("td", {}, h("span", { class: "badge tactic" }, t.tactic || "")),
      h("td", {}, t.technique || ""),
      h("td", {}, t.computer || ""),
      h("td", { class: "summary" }, t.summary || ""),
      h("td", {}, stateBadge),
      h("td", {}, action),
    ]));
  });
  table.appendChild(body);

  pane.appendChild(h("div", {}, [h("h3", {}, `Timeline (${(data.timeline || []).length} events)`), table]));
}

// ============================================================================
// IOC tab
// ============================================================================
async function renderIOCs(pane, caseID) {
  pane.innerHTML = `<div class="empty"><span class="spinner"></span>loading IOCs…</div>`;
  let iocs;
  try { iocs = await api("GET", `/api/cases/${encodeURIComponent(caseID)}/iocs`); }
  catch (e) { pane.innerHTML = `<div class="empty">No synthesis yet.</div>`; return; }

  pane.innerHTML = "";
  pane.appendChild(h("div", { class: "row", style: "margin-bottom: 12px;" }, [
    h("a", { href: `/api/cases/${encodeURIComponent(caseID)}/report/csv/iocs`, download: "iocs.csv" },
       h("button", {}, "Download CSV")),
  ]));

  if (!iocs || iocs.length === 0) {
    pane.appendChild(h("div", { class: "empty" }, "No IOCs extractable."));
    return;
  }
  const groups = new Map();
  iocs.forEach((i) => {
    const k = i.type;
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(i);
  });
  for (const [type, list] of [...groups.entries()].sort()) {
    const tbl = h("table", { class: "ioc-table" });
    list.forEach((i) => {
      tbl.appendChild(h("tr", {}, [
        h("td", { class: "value", style: "width: 60%;" }, i.value),
        h("td", { style: "width: 10%;" }, "×" + i.count),
        h("td", { class: "src" }, (i.findings || []).join(", ") + " · " + (i.tactics || []).join(",")),
      ]));
    });
    pane.appendChild(h("div", { class: "ioc-group" }, [
      h("h3", {}, [type, h("span", { class: "count" }, `(${list.length})`)]),
      tbl,
    ]));
  }
}

// ============================================================================
// MITRE tab
// ============================================================================
async function renderMITRE(pane, caseID) {
  pane.innerHTML = `<div class="empty"><span class="spinner"></span>loading MITRE map…</div>`;
  let mapping;
  try { mapping = await api("GET", `/api/cases/${encodeURIComponent(caseID)}/mitre`); }
  catch (e) { pane.innerHTML = `<div class="empty">No synthesis yet.</div>`; return; }

  pane.innerHTML = "";
  if (!mapping || mapping.length === 0) {
    pane.appendChild(h("div", { class: "empty" }, "No MITRE mappings."));
    return;
  }
  // Group by tactic
  const byTactic = new Map();
  mapping.forEach((m) => {
    const k = m.tactic;
    if (!byTactic.has(k)) byTactic.set(k, { name: m.tactic_name, items: [] });
    byTactic.get(k).items.push(m);
  });

  const grid = h("div", { class: "mitre-matrix" });
  for (const [tac, g] of [...byTactic.entries()].sort()) {
    grid.appendChild(h("div", { class: "tactic-col" }, [
      h("div", { class: "id" }, tac),
      h("div", { class: "name" }, g.name || tac),
    ]));
    const row = h("div", { class: "technique-row" });
    g.items.forEach((m) => {
      const cell = h("div", { class: "mitre-cell " + (m.confidence || "low") }, [
        h("div", { class: "id" }, m.technique || ""),
        h("div", { class: "name" }, m.technique_name || ""),
        h("div", { class: "count" }, `${m.finding_count} finding · ${m.evidence_count} evidence`),
      ]);
      cell.onclick = () => navigate(`/cases/${encodeURIComponent(caseID)}?tab=findings`);
      row.appendChild(cell);
    });
    grid.appendChild(row);
  }
  pane.appendChild(grid);
}

// ============================================================================
// Report tab
// ============================================================================
async function renderReport(pane, caseID) {
  pane.innerHTML = "";
  pane.appendChild(h("div", { class: "row", style: "margin-bottom: 12px; align-items: center;" }, [
    h("a", { href: `/api/cases/${encodeURIComponent(caseID)}/report/html`, target: "_blank" },
       h("button", {}, "Open HTML")),
    h("a", { href: `/api/cases/${encodeURIComponent(caseID)}/report/csv/findings`, download: "findings.csv" },
       h("button", {}, "Findings CSV")),
    h("a", { href: `/api/cases/${encodeURIComponent(caseID)}/report/csv/timeline`, download: "timeline.csv" },
       h("button", {}, "Timeline CSV")),
    h("a", { href: `/api/cases/${encodeURIComponent(caseID)}/report/csv/iocs`, download: "iocs.csv" },
       h("button", {}, "IOC CSV")),
    h("a", { href: `/api/cases/${encodeURIComponent(caseID)}/report/json`, download: "report.json" },
       h("button", {}, "JSON")),
  ]));

  // Try to fetch and embed HTML inside an iframe
  try {
    const r = await fetch(`/api/cases/${encodeURIComponent(caseID)}/report/html`);
    if (!r.ok) {
      pane.appendChild(h("div", { class: "empty" }, "No HTML report yet — click 'Generate Report' above."));
      return;
    }
    const html = await r.text();
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    pane.appendChild(h("iframe", { class: "report-frame", src: url }));
  } catch (e) {
    pane.appendChild(h("div", { class: "empty" }, "Report not available: " + e.message));
  }
}

// ============================================================================
// Audit tab
// ============================================================================
async function renderAudit(pane, caseID) {
  pane.innerHTML = `<div class="empty"><span class="spinner"></span>loading audit…</div>`;
  let entries;
  try { entries = await api("GET", `/api/cases/${encodeURIComponent(caseID)}/audit`); }
  catch (e) { pane.innerHTML = `<div class="empty">No audit log.</div>`; return; }

  pane.innerHTML = "";
  // Tier filter
  const tiers = ["", "tier0", "tier1", "tier2", "tier3"];
  const filter = h("select", { id: "audit_tier", style: "max-width: 200px;" },
    tiers.map((t) => h("option", { value: t }, t || "(all tiers)"))
  );
  filter.onchange = async () => {
    const v = filter.value;
    let url = `/api/cases/${encodeURIComponent(caseID)}/audit`;
    if (v) url += "?tier=" + encodeURIComponent(v);
    const data = await api("GET", url);
    redrawAudit(list, data);
  };
  pane.appendChild(h("div", { class: "row", style: "margin-bottom: 12px; align-items: center;" }, [
    h("span", { class: "muted" }, "Tier filter:"), filter,
  ]));

  const list = h("div", { class: "audit-list" });
  pane.appendChild(list);
  redrawAudit(list, entries);
}

function redrawAudit(list, entries) {
  list.innerHTML = "";
  if (!entries || entries.length === 0) {
    list.appendChild(h("div", { class: "empty" }, "No audit entries."));
    return;
  }
  entries.forEach((e) => {
    const failed = e.success === false;
    // Top-line summary (always single-line, truncates via CSS).
    const summary = [];
    if (e.artifact_id) summary.push("artifact=" + e.artifact_id);
    if (e.row_count != null) summary.push("rows=" + e.row_count);
    if (e.duration_seconds != null) summary.push("dur=" + e.duration_seconds.toFixed(2) + "s");
    if (e.success != null) summary.push("ok=" + e.success);
    // Detail block: full command + error + any extra fields, wrap & scroll.
    const detailLines = [];
    if (e.command) detailLines.push("$ " + e.command);
    if (e.stdout_tail) detailLines.push("--- stdout (tail) ---\n" + e.stdout_tail);
    if (e.stderr_tail) detailLines.push("--- stderr (tail) ---\n" + e.stderr_tail);
    if (e.error) detailLines.push("ERROR: " + e.error);
    // REQ-1 nested_extract audit shape (no command, but has src/dst/result).
    if (e.kind === "nested_extract") {
      const extra = [];
      if (e.format) extra.push("format=" + e.format);
      if (e.src) extra.push("src=" + e.src);
      if (e.dst_dir) extra.push("dst=" + e.dst_dir);
      if (e.depth != null) extra.push("depth=" + e.depth);
      if (e.members != null) extra.push("members=" + e.members);
      if (e.bytes_uncompressed != null) extra.push("bytes=" + e.bytes_uncompressed);
      if (e.compression_ratio != null) extra.push("ratio=" + e.compression_ratio);
      if (e.result) extra.push("result=" + e.result);
      detailLines.push(extra.join("\n"));
    }
    const hasDetail = detailLines.length > 0;
    const detail = hasDetail
      ? h("pre", { class: "audit-detail" }, detailLines.join("\n\n"))
      : null;
    const summaryEl = h("span", { class: "body" }, summary.join(" · "));
    const toggle = hasDetail
      ? h("button", {
          class: "audit-toggle",
          title: "Show full command / output",
          onclick: (ev) => {
            ev.preventDefault();
            const row = ev.currentTarget.closest(".audit-item");
            const exp = row.classList.toggle("expanded");
            ev.currentTarget.textContent = exp ? "▾" : "▸";
          },
        }, "▸")
      : h("span", { class: "audit-toggle-placeholder" }, " ");
    const row = h("div", { class: "audit-item" + (failed ? " failed" : "") }, [
      toggle,
      h("span", { class: "ts" }, fmtTS(e.ts)),
      h("span", { class: "actor" }, e.actor || ""),
      h("span", { class: "kind" }, e.kind || ""),
      summaryEl,
    ]);
    if (detail) {
      row.appendChild(detail);
    }
    list.appendChild(row);
  });
}

// ============================================================================
// Status tab — pipeline overview + in-memory event log (Wave 20g)
// ============================================================================
// Centralises what the four /api/cases/<id>/{parse,analyze,synthesize,report}/status
// endpoints already serve so the examiner can see "where are we, what's
// happening right now, what has happened" without scrolling the case
// detail page. No backend changes: this tab is a pure aggregation +
// event-log buffer over existing JobStatus polling.
//
// Re-uses pipelinePolls? No — pipelinePolls is owned by the header
// pipeline bar (renderPipeline). The Status tab owns its own interval
// so navigating away cleanly stops polling. The header bar keeps its
// own ticks so the pipeline buttons stay live in every tab.

const statusEventLog = [];   // in-memory, in-page-load only (no persistence)
const STATUS_EVENT_CAP = 200;
let statusTabPollID = null;

const STATUS_PHASES = [
  { kind: "parse",      label: "① Parse",     subpath: "parse" },
  { kind: "analyze",    label: "② Analyze",   subpath: "analyze" },
  { kind: "synthesize", label: "③ Synthesize", subpath: "synthesize" },
  { kind: "report",     label: "④ Report",    subpath: "report" },
  { kind: "autopilot",  label: "🤖 Auto-pilot", subpath: "autopilot" }, // Wave 34
];

function statusPushEvent(caseID, kind, before, now) {
  // Only push when something meaningful changed: state transition, or a new
  // progress text / counter step. Without this, every 2s poll would log a
  // duplicate row even when nothing happened.
  if (!before) {
    if ((now.state || "idle") !== "idle") {
      statusEventLog.unshift({
        ts: Date.now(), caseID, kind,
        text: `${kind} ${now.state}` + (now.progress ? ` · ${now.progress}` : ""),
        kind_state: now.state,
      });
    }
    return;
  }
  const changedState  = before.state !== now.state;
  const changedProg   = (before.progress || "") !== (now.progress || "");
  const changedCount  = (before.current || 0) !== (now.current || 0);
  if (!changedState && !changedProg && !changedCount) return;
  let text = `${kind}: ${now.state || "idle"}`;
  if (now.progress) text += ` · ${now.progress}`;
  if (now.total > 0) text += ` (${now.current}/${now.total})`;
  if (now.state === "failed" && now.error) text += ` — ${now.error.slice(0, 200)}`;
  statusEventLog.unshift({
    ts: Date.now(), caseID, kind, text, kind_state: now.state,
  });
  if (statusEventLog.length > STATUS_EVENT_CAP) {
    statusEventLog.length = STATUS_EVENT_CAP;
  }
}

function statusPhaseBadgeClass(state) {
  if (state === "running")   return "badge warn";
  if (state === "succeeded") return "badge ok";
  if (state === "failed")    return "badge err";
  if (state === "canceled")  return "badge missing";
  return "badge missing";  // idle
}

function statusPhaseSymbol(state) {
  if (state === "running")   return "▶";
  if (state === "succeeded") return "✓";
  if (state === "failed")    return "✗";
  if (state === "canceled")  return "⊘";
  return "·";  // idle
}

function statusFmtClock(ms) {
  const d = new Date(ms);
  // HH:MM:SS local time. Examiner is on SIFT (UTC) so this matches case TZ.
  return d.toISOString().slice(11, 19);
}

async function renderStatus(pane, caseID) {
  // Stop any previous Status-tab poll so navigating between cases cleans up.
  if (statusTabPollID !== null) {
    clearInterval(statusTabPollID);
    statusTabPollID = null;
  }

  pane.innerHTML = "";

  // Pipeline overview row — one card per phase.
  const overview = h("div", { class: "status-overview", id: "status_overview" });
  pane.appendChild(overview);

  // Per-phase detail blocks. Each is a .card with a header row + progress
  // block (reuses the existing renderProgressBlock styles so the visual
  // language matches the header pipeline bar).
  const detailWrap = h("div", { class: "status-details", id: "status_details" });
  pane.appendChild(detailWrap);

  // Event log section.
  const logSection = h("div", { class: "card", style: "margin-top: 16px;" }, [
    h("div", { class: "card-header" }, [
      h("strong", {}, "Event log"),
      h("span", { class: "muted", style: "margin-left: 8px; font-size: 12px;" },
        "(in-memory, current page-load)"),
    ]),
    h("div", { id: "status_event_log", class: "status-event-log" }),
  ]);
  pane.appendChild(logSection);

  // Previous JobStatus snapshot, used by statusPushEvent for delta detection.
  const lastByKind = {};

  async function tick() {
    let anyRunning = false;
    const results = {};
    for (const phase of STATUS_PHASES) {
      try {
        const st = await api("GET",
          `/api/cases/${encodeURIComponent(caseID)}/${phase.subpath}/status`);
        results[phase.kind] = st;
        statusPushEvent(caseID, phase.kind, lastByKind[phase.kind], st);
        lastByKind[phase.kind] = st;
        if (st.state === "running") anyRunning = true;
      } catch (_) {
        results[phase.kind] = { state: "idle" };
      }
    }
    paintOverview(overview, results);
    paintDetails(detailWrap, caseID, results);
    paintEventLog($("#status_event_log", pane));
    return anyRunning;
  }

  await tick();
  // Poll every 2 s. Same cadence as pipelinePolls so the two views agree.
  statusTabPollID = setInterval(tick, 2000);
}

function paintOverview(host, results) {
  const sig = JSON.stringify(STATUS_PHASES.map((p) => {
    const r = results[p.kind] || {};
    return [p.kind, r.state, r.current, r.total];
  }));
  if (host.dataset.sig === sig) return;
  host.dataset.sig = sig;
  host.innerHTML = "";

  STATUS_PHASES.forEach((p, i) => {
    const st = results[p.kind] || { state: "idle" };
    const card = h("div", { class: "status-phase " + (st.state || "idle") }, [
      h("div", { class: "status-phase-symbol" }, statusPhaseSymbol(st.state)),
      h("div", { class: "status-phase-label" }, p.label),
      h("div", { class: statusPhaseBadgeClass(st.state) }, st.state || "idle"),
    ]);
    host.appendChild(card);
    if (i < STATUS_PHASES.length - 1) {
      host.appendChild(h("span", { class: "status-arrow" }, "→"));
    }
  });
}

function paintDetails(host, caseID, results) {
  host.innerHTML = "";
  STATUS_PHASES.forEach((p) => {
    const st = results[p.kind] || { state: "idle" };
    const card = h("div", { class: "card status-detail-card" });
    const header = h("div", { class: "card-header" }, [
      h("strong", {}, p.label),
      h("span", { class: statusPhaseBadgeClass(st.state),
                  style: "margin-left: 8px;" }, st.state || "idle"),
    ]);
    card.appendChild(header);

    const body = h("div", { style: "padding: 10px 14px;" });
    // Re-use the progress-block renderer so visual language matches the
    // header pipeline bar — single source of truth for "what does running
    // look like" / "what does failed look like".
    const block = h("div", { class: "progress-block " + (st.state || "idle") });
    renderProgressBlock(block, { ...st, case_id: caseID, kind: p.kind });
    body.appendChild(block);

    // Extra timestamps the header bar omits but a status board should show.
    const meta = [];
    if (st.started_at)  meta.push("started "  + statusFmtClock(Date.parse(st.started_at)));
    if (st.finished_at && st.state !== "running") {
      meta.push("finished " + statusFmtClock(Date.parse(st.finished_at)));
    }
    if (st.subkind && st.subkind !== "all" && st.subkind !== "") {
      meta.push("scope=" + st.subkind);
    }
    if (meta.length) {
      body.appendChild(h("div", {
        class: "muted",
        style: "font-size: 11px; margin-top: 6px;",
      }, meta.join("  ·  ")));
    }
    card.appendChild(body);
    host.appendChild(card);
  });
}

function paintEventLog(host) {
  if (!host) return;
  if (statusEventLog.length === 0) {
    host.innerHTML = '<div class="empty">No events yet. Run Parse / Analyze / Synthesize / Report to populate.</div>';
    return;
  }
  // Render only recent N; signature-guard against repaint.
  const recent = statusEventLog.slice(0, 80);
  const sig = recent.length + ":" + (recent[0]?.ts || 0);
  if (host.dataset.sig === sig) return;
  host.dataset.sig = sig;
  host.innerHTML = "";
  recent.forEach((ev) => {
    const row = h("div", { class: "status-event-row " + (ev.kind_state || "") }, [
      h("span", { class: "status-event-ts" }, statusFmtClock(ev.ts)),
      h("span", { class: "status-event-kind " + (ev.kind_state || "") }, ev.kind),
      h("span", { class: "status-event-text" }, ev.text),
    ]);
    host.appendChild(row);
  });
}

// ============================================================================
// Events tab — view parsed unified_events + parse_results
// ============================================================================
// renderExtractsSection draws the "Extracts" panel above the Parse Results
// table (Issue #23). Only renders when the case has an extract.log — for
// non-image cases the GET returns total=0 and we skip the section.
async function renderExtractsSection(pane, caseID) {
  let data = null;
  try {
    data = await api("GET", `/api/cases/${encodeURIComponent(caseID)}/extracts`);
  } catch (_) { return; }
  if (!data || (data.total | 0) === 0) return;

  // Bug fix: this function is called recursively after every approve/reject,
  // but the original implementation only appended a new section without
  // removing the previous one — clicking N buttons produced N stacked tables.
  // Drop any prior incarnation before appending.
  const old = pane.querySelector(".extracts-section");
  if (old) old.remove();

  const exSection = h("div", { class: "card extracts-section" });
  exSection.appendChild(h("h2", {}, "Extracts — Review Gate 0 (image)"));
  const hdr = data.header || {};
  const c = data.counts || {};
  exSection.appendChild(h("div", { class: "muted", style: "margin-bottom: 8px;" },
    `image: ${hdr.image_path || "?"} · format: ${hdr.image_format || "?"} · ` +
    `mount: ${hdr.mount_method || "?"} · ` +
    `approved=${c.approved||0} · pending=${c.pending||0} · rejected=${c.rejected||0}`));

  const tbl = h("table", { class: "events-table" });
  tbl.appendChild(h("thead", {}, h("tr", {}, [
    h("th", {}, "Target"),
    h("th", {}, "Status"),
    h("th", {}, "Part"),
    h("th", {}, "Inum"),
    h("th", {}, "Bytes"),
    h("th", {}, "SHA-256"),
    h("th", {}, "Review"),
    h("th", {}, "Action"),
  ])));
  const body = h("tbody");
  (data.records || []).forEach((r) => {
    const stateClass = {
      approved: "approved", rejected: "rejected", pending: "pending",
    }[r.state] || "pending";
    const stateBadge = h("span", { class: "badge " + stateClass,
      title: r.reason || r.error || "" }, r.state || "pending");
    const action = h("div", { class: "row", style: "gap: 4px;" });
    if (r.state === "approved" || r.state === "rejected") {
      action.appendChild(h("span", { class: "muted", style: "font-size: 10px;" },
        (r.reviewed_by || "?") + " · " + fmtTS(r.reviewed_at).slice(0, 16)));
    } else {
      action.appendChild(h("button", {
        onclick: async () => {
          try {
            await api("POST",
              `/api/cases/${encodeURIComponent(caseID)}/extracts/${encodeURIComponent(r.target)}/approve`);
            toast("Approved " + r.target, "success");
            await renderExtractsSection(pane, caseID);
          } catch (e) { toast(e.message, "error"); }
        },
      }, "Approve"));
      action.appendChild(h("button", {
        class: "danger",
        onclick: () => {
          const close = modal([
            h("h3", {}, "Reject extract " + r.target),
            h("div", { class: "form-row" }, [h("label", {}, "Reason (optional)"),
              h("input", { id: "ex_reason", placeholder: "why is this extract bad? (optional)" })]),
            h("div", { class: "actions" }, [
              h("button", { class: "ghost", onclick: () => close() }, "Cancel"),
              h("button", { class: "danger", onclick: async () => {
                try {
                  await api("POST",
                    `/api/cases/${encodeURIComponent(caseID)}/extracts/${encodeURIComponent(r.target)}/reject`,
                    { reason: $("#ex_reason").value.trim() });
                  close(); toast("Rejected " + r.target, "success");
                  await renderExtractsSection(pane, caseID);
                } catch (e) { toast(e.message, "error"); }
              }}, "Reject"),
            ]),
          ]);
        },
      }, "Reject"));
    }
    const statusClass = r.status === "ok" ? "ok"
                      : r.status === "not_found" ? "pending"
                      : r.status === "skip" ? "pending"
                      : "err";
    body.appendChild(h("tr", {}, [
      h("td", {}, h("code", {}, r.target)),
      h("td", {}, h("span", { class: "badge " + statusClass, title: r.error || "" }, r.status)),
      h("td", {}, r.partition != null ? String(r.partition) : "—"),
      h("td", { class: "mono" }, r.inum || "—"),
      h("td", {}, r.bytes != null ? Number(r.bytes).toLocaleString() : "—"),
      h("td", { class: "mono", style: "font-size: 10px;" },
        r.sha256 ? r.sha256.slice(0, 16) + "…" : "—"),
      h("td", {}, stateBadge),
      h("td", {}, action),
    ]));
  });
  tbl.appendChild(body);
  exSection.appendChild(tbl);
  // Always position the Extracts section above Parse Results — `insertBefore`
  // with the current first child keeps the layout stable across re-renders
  // (approve/reject would otherwise append to the bottom).
  if (pane.firstChild) {
    pane.insertBefore(exSection, pane.firstChild);
  } else {
    pane.appendChild(exSection);
  }
}

async function renderEvents(pane, caseID, detail) {
  pane.innerHTML = "";

  // ---------- Extracts (Issue #23) ----------
  // Renders only when extract.log exists (i.e. the evidence was a disk
  // image and image_extractor.py ran). Otherwise the section is silently
  // omitted so non-image cases stay clean.
  await renderExtractsSection(pane, caseID);

  // ---------- Parse Results + Review Gate 0 ----------
  const prSection = h("div", { class: "card" });
  prSection.appendChild(h("h2", {}, "Parse Results — Review Gate 0"));
  const prs = (detail && detail.parse_results) || [];

  // Pull current per-artifact review state so we can render approve/reject
  // controls in-line. Treat fetch failure as "all pending" rather than
  // hiding the table.
  let review = { auto_skip: false, reviews: {}, counts: {} };
  try {
    review = await api("GET", `/api/cases/${encodeURIComponent(caseID)}/parse-review`);
  } catch (_) { /* fine */ }

  if (prs.length === 0) {
    prSection.appendChild(h("div", { class: "empty" },
      "No parse results yet. Run Parse from the pipeline buttons above."));
  } else {
    // Header banner: roll-up + skip-all toggle
    const c = review.counts || {};
    const banner = h("div", { class: "row", style: "align-items: center; margin-bottom: 8px; gap: 12px;" }, [
      h("span", { class: "muted" },
        `${prs.length} artifacts · approved=${c.approved||0} · pending=${c.pending||0} · ` +
        `rejected=${c.rejected||0} · skipped=${c.skipped||0}`),
      h("span", { class: "spacer" }),
      h("label", { style: "display: flex; gap: 6px; align-items: center; font-size: 11px; cursor: pointer;" }, [
        h("input", {
          type: "checkbox", id: "gate0-skip-all",
          ...(review.auto_skip ? { checked: "checked" } : {}),
          onchange: async (ev) => {
            try {
              await api("POST", `/api/cases/${encodeURIComponent(caseID)}/parse-review/skip-all`,
                { auto_skip: ev.target.checked });
              toast(ev.target.checked ? "Gate 0 skipped (all)" : "Gate 0 re-enabled", "success");
              await renderEvents($("#tabpane"), caseID, detail);
            } catch (e) { toast(e.message, "error"); }
          },
        }),
        "Skip Review Gate 0 (auto-approve all)",
      ]),
    ]);
    prSection.appendChild(banner);

    // Wave 15: 4-status classification (OK / EMPTY / NOT_PRESENT / FAIL).
    // The NOT_PRESENT sentinel is set by parsers/orchestrator.py when an
    // implemented artefact wasn't found in the input — Review Gate 0 then
    // shows a complete picture of every implemented artefact, not just the
    // detected ones.
    const prStatus = (pr) => {
      const cmd = pr.command || "";
      if (cmd.startsWith("(not present")) {
        return { kind: "not_present", label: "NOT_PRESENT", badge: "missing",
                 hint: "artefact not present in input" };
      }
      if (pr.exit_code === 0 && (pr.row_count || 0) > 0) {
        return { kind: "ok",      label: "OK",          badge: "ok",
                 hint: "exit=0 · rows=" + (pr.row_count || 0) };
      }
      if (pr.exit_code === 0) {
        return { kind: "empty",   label: "EMPTY",       badge: "warn",
                 hint: "exit=0 but 0 rows" };
      }
      return     { kind: "fail",    label: "FAIL",        badge: "err",
                   hint: "exit=" + (pr.exit_code != null ? pr.exit_code : "?") };
    };
    const statusRank = { ok: 0, empty: 1, not_present: 2, fail: 3 };
    const prsSorted = prs.slice().sort((a, b) => {
      const ra = statusRank[prStatus(a).kind] ?? 9;
      const rb = statusRank[prStatus(b).kind] ?? 9;
      if (ra !== rb) return ra - rb;
      return (a.artifact_id || "").localeCompare(b.artifact_id || "");
    });

    const tbl = h("table", { class: "events-table" });
    tbl.appendChild(h("thead", {}, h("tr", {}, [
      h("th", {}, "Artifact"),
      h("th", {}, "Status"),
      h("th", {}, "Rows"),
      h("th", {}, "Duration"),
      h("th", {}, "Started"),
      h("th", {}, "Review"),
      h("th", {}, "Action"),
      h("th", {}, "Analyze"),  // Wave 20h: artifact-scoped LLM run
    ])));
    const body = h("tbody");
    prsSorted.forEach((pr) => {
      const st = prStatus(pr);
      const isNP = st.kind === "not_present";
      const ok = pr.exit_code != null && pr.exit_code === 0;
      const dur = isNP ? "—"
        : (pr.finished_at && pr.started_at)
        ? ((new Date(pr.finished_at) - new Date(pr.started_at)) / 1000).toFixed(2) + "s"
        : "—";
      const aid = pr.artifact_id || "?";
      const rev = (review.reviews && review.reviews[aid]) || { state: "pending" };
      const stateClass = {
        approved: "approved", rejected: "rejected",
        skipped:  "pending",  pending:  "pending",
      }[rev.state] || "pending";
      const stateBadge = h("span", { class: "badge " + stateClass, title: rev.reason || "" }, rev.state || "pending");

      const action = h("div", { class: "row", style: "gap: 4px;" });
      if (rev.state === "approved" || rev.state === "rejected") {
        action.appendChild(h("span", { class: "muted", style: "font-size: 10px;" },
          (rev.reviewed_by || "?") + " · " + fmtTS(rev.reviewed_at).slice(0, 16)));
      } else {
        action.appendChild(h("button", {
          onclick: async () => {
            try {
              await api("POST", `/api/cases/${encodeURIComponent(caseID)}/parse-review/${encodeURIComponent(aid)}/approve`);
              toast("Approved " + aid, "success");
              await renderEvents($("#tabpane"), caseID, detail);
            } catch (e) { toast(e.message, "error"); }
          },
        }, "Approve"));
        action.appendChild(h("button", {
          class: "danger",
          onclick: () => {
            const close = modal([
              h("h3", {}, "Reject parse result " + aid),
              h("div", { class: "form-row" }, [h("label", {}, "Reason"),
                h("input", { id: "pr_reason", placeholder: "why is this parser output bad?" })]),
              h("div", { class: "actions" }, [
                h("button", { class: "ghost", onclick: () => close() }, "Cancel"),
                h("button", { class: "danger", onclick: async () => {
                  try {
                    await api("POST", `/api/cases/${encodeURIComponent(caseID)}/parse-review/${encodeURIComponent(aid)}/reject`,
                      { reason: $("#pr_reason").value.trim() });
                    close(); toast("Rejected " + aid, "success");
                    await renderEvents($("#tabpane"), caseID, detail);
                  } catch (e) { toast(e.message, "error"); }
                }}, "Reject"),
              ]),
            ]);
          },
        }, "Reject"));
      }

      // Wave 20h: per-artifact Analyze button. Only shown for rows with
      // actual data (OK). Empty / failed / not_present rows wouldn't
      // produce meaningful LLM output; the button is omitted to avoid
      // burning model budget on guaranteed-empty scans.
      const analyzeCell = h("td", {});
      if (st.kind === "ok") {
        analyzeCell.appendChild(h("button", {
          class: "ghost",
          style: "padding: 2px 8px; font-size: 11px;",
          title: `Run relevant Tactic Agents scoped to artifact_id="${aid}". `
                + `Server picks the tactics whose SQL prefilter references this artifact.`,
          onclick: async () => {
            if (!confirm(`Analyze "${aid}" with relevant tactics?\n\n`
                + `LLM cost: ~1-3 tactics × Claude run. Findings will be saved to `
                + `outputs/cases/${caseID}/findings/by-artifact/${aid}/.`)) {
              return;
            }
            try {
              const resp = await api("POST",
                `/api/cases/${encodeURIComponent(caseID)}/analyze/artifact/${encodeURIComponent(aid)}`);
              toast(`analyze artifact=${aid} started · check Status tab`, "success");
              // If user is currently NOT on Status tab, hint that progress
              // is visible there.
            } catch (e) {
              toast(`analyze artifact=${aid} failed: ${e.message}`, "error");
            }
          },
        }, "▶ Analyze"));
      } else {
        analyzeCell.appendChild(h("span", { class: "muted", style: "font-size: 10px;" }, "—"));
      }

      body.appendChild(h("tr", { class: isNP ? "pr-row-not-present" : "" }, [
        h("td", {}, h("span", { class: "badge tactic" }, aid)),
        h("td", {}, h("span", { class: "badge " + st.badge, title: st.hint }, st.label)),
        h("td", {}, isNP ? "—" : (pr.row_count != null ? pr.row_count.toLocaleString() : "—")),
        h("td", {}, dur),
        h("td", { class: "ts" }, isNP ? "—" : fmtTS(pr.started_at)),
        h("td", {}, stateBadge),
        h("td", {}, action),
        h("td", {}, analyzeCell),
      ]));
    });
    tbl.appendChild(body);
    prSection.appendChild(tbl);

    if (!review.all_approved_or_skipped && prs.length > 0) {
      prSection.appendChild(h("div", { class: "muted", style: "margin-top: 8px; font-size: 11px;" },
        "⚠ Analyze All / Analyze single tactic は、全アーティファクトを Approve するか" +
        "「Skip Review Gate 0」を有効化するまでブロックされます。"));
    }
  }
  pane.appendChild(prSection);

  // ---------- Events Browser ----------
  const browserCard = h("div", { class: "card" });
  browserCard.appendChild(h("h2", {}, "Events Browser"));
  browserCard.appendChild(h("div", { class: "muted", style: "margin-bottom: 8px;" },
    `Total events parsed: ${detail.case.unified_event_rows.toLocaleString()}. ` +
    "Use the filters below to query the unified_events table."));

  // Filter form
  const artifactIDs = [...new Set(prs.map((p) => p.artifact_id).filter(Boolean))].sort();
  const filterRow = h("div", { class: "filter-row" }, [
    h("div", { class: "f-field" }, [
      h("label", {}, "Artifact"),
      h("select", { id: "ev_artifact" },
        [h("option", { value: "" }, "(all)"),
         ...artifactIDs.map((a) => h("option", { value: a }, a))]),
    ]),
    h("div", { class: "f-field" }, [
      h("label", {}, "Computer (exact)"),
      h("input", { id: "ev_computer", placeholder: "e.g. IEWIN7" }),
    ]),
    h("div", { class: "f-field" }, [
      h("label", {}, "Contains"),
      h("input", { id: "ev_contains", placeholder: "substring in payload" }),
    ]),
    h("div", { class: "f-field" }, [
      h("label", {}, "Start (UTC)"),
      h("input", { id: "ev_start", placeholder: "2019-02-13T00:00:00Z" }),
    ]),
    h("div", { class: "f-field" }, [
      h("label", {}, "End (UTC)"),
      h("input", { id: "ev_end", placeholder: "2019-02-15T00:00:00Z" }),
    ]),
    h("div", { class: "f-field" }, [
      h("label", {}, "Limit"),
      h("input", { id: "ev_limit", value: "100", style: "max-width: 80px;" }),
    ]),
    h("div", { class: "f-field" }, [
      h("label", {}, "Offset"),
      h("input", { id: "ev_offset", value: "0", style: "max-width: 80px;" }),
    ]),
    h("div", { class: "f-field", style: "align-self: end;" }, [
      h("button", {
        class: "primary",
        onclick: () => loadEventsPage(caseID, browserCard, 0),
      }, "Search"),
    ]),
  ]);
  browserCard.appendChild(filterRow);

  // Results placeholder
  const resultsBox = h("div", { id: "ev_results", style: "margin-top: 12px;" });
  browserCard.appendChild(resultsBox);

  pane.appendChild(browserCard);

  // Initial load: first 100 events with no filter — gives the user something
  // immediate to look at instead of an empty table.
  await loadEventsPage(caseID, browserCard, 0);
}

async function loadEventsPage(caseID, browserCard, offsetOverride) {
  const resultsBox = browserCard.querySelector("#ev_results");
  resultsBox.innerHTML = `<div class="empty"><span class="spinner"></span>querying…</div>`;

  const q = new URLSearchParams();
  const artifact = browserCard.querySelector("#ev_artifact").value;
  const computer = browserCard.querySelector("#ev_computer").value.trim();
  const contains = browserCard.querySelector("#ev_contains").value.trim();
  const start    = browserCard.querySelector("#ev_start").value.trim();
  const end      = browserCard.querySelector("#ev_end").value.trim();
  const limit    = parseInt(browserCard.querySelector("#ev_limit").value, 10) || 100;
  let offset     = (offsetOverride != null)
    ? offsetOverride
    : parseInt(browserCard.querySelector("#ev_offset").value, 10) || 0;
  browserCard.querySelector("#ev_offset").value = offset;

  if (artifact) q.set("artifact_id", artifact);
  if (computer) q.set("computer", computer);
  if (contains) q.set("contains", contains);
  if (start)    q.set("start", start);
  if (end)      q.set("end", end);
  q.set("limit", limit);
  q.set("offset", offset);

  let data;
  try {
    data = await api("GET", `/api/cases/${encodeURIComponent(caseID)}/events?${q.toString()}`);
  } catch (e) {
    resultsBox.innerHTML = "";
    resultsBox.appendChild(h("div", { class: "empty" }, "Query failed: " + e.message));
    return;
  }

  resultsBox.innerHTML = "";
  // Summary line + paging buttons
  resultsBox.appendChild(h("div", { class: "row", style: "align-items: center; margin-bottom: 8px;" }, [
    h("span", { class: "muted" },
      `Showing ${data.events ? data.events.length : 0} events  ` +
      `(offset=${offset}, limit=${limit})`),
    h("span", { class: "spacer" }),
    h("button", {
      class: "ghost",
      disabled: offset === 0 ? "disabled" : null,
      onclick: () => loadEventsPage(caseID, browserCard, Math.max(0, offset - limit)),
    }, "« Prev"),
    h("button", {
      class: "ghost",
      disabled: (data.events && data.events.length < limit) ? "disabled" : null,
      onclick: () => loadEventsPage(caseID, browserCard, offset + limit),
    }, "Next »"),
  ]));

  if (!data.events || data.events.length === 0) {
    resultsBox.appendChild(h("div", { class: "empty" }, "No events match these filters."));
    return;
  }

  const tbl = h("table", { class: "events-table" });
  tbl.appendChild(h("thead", {}, h("tr", {}, [
    h("th", {}, "Timestamp (UTC)"),
    h("th", {}, "Artifact"),
    h("th", {}, "Event Type"),
    h("th", {}, "Computer"),
    h("th", {}, "Audit ID"),
    h("th", {}, "Payload"),
  ])));
  const body = h("tbody");
  data.events.forEach((e) => {
    const previewBtn = h("button", { class: "ghost",
      onclick: () => showPayloadModal(e),
    }, "view");
    body.appendChild(h("tr", {}, [
      h("td", { class: "ts" }, fmtTS(e.ts_utc)),
      h("td", {}, h("span", { class: "badge tactic" }, e.artifact_id || "")),
      h("td", {}, e.event_type || ""),
      h("td", {}, e.computer || ""),
      h("td", { class: "audit-id-cell" }, (e.audit_id || "").slice(0, 12) + "…"),
      h("td", {}, previewBtn),
    ]));
  });
  tbl.appendChild(body);
  resultsBox.appendChild(tbl);
}

function showPayloadModal(ev) {
  let pretty = ev.payload_json || "";
  try {
    pretty = JSON.stringify(JSON.parse(ev.payload_json), null, 2);
  } catch (_) { /* leave as-is */ }
  const close = modal([
    h("h3", {}, "Event payload"),
    h("div", { class: "muted", style: "margin-bottom: 8px;" },
      `${ev.artifact_id} · ${ev.event_type} · ${ev.computer || "(no host)"} · ${fmtTS(ev.ts_utc)}`),
    h("div", { class: "muted", style: "margin-bottom: 8px;" }, "audit_id: " + (ev.audit_id || "")),
    h("pre", { class: "payload-pre" }, pretty),
    h("div", { class: "actions" }, [
      h("button", {
        class: "ghost",
        onclick: () => {
          navigator.clipboard.writeText(pretty)
            .then(() => toast("payload copied", "success"))
            .catch(() => toast("clipboard blocked", "error"));
        },
      }, "Copy JSON"),
      h("button", { class: "primary", onclick: () => close() }, "Close"),
    ]),
  ]);
}

// ============================================================================
// Chat assistant — floating FAB + slide-in drawer
//
// Mounted once at DOMContentLoaded; survives hash-route changes. The current
// case_id (if any) is read from the URL each time a message is sent so the
// server can attach case context to the system prompt.
//
// Privacy: the user's first send each session triggers a one-shot warning
// that case data will be transmitted. Stored in localStorage as a flag.
// History is browser-local only (key: findevil:chat:<caseID|global>).
// ============================================================================

const CHAT_STORAGE_PREFIX = "findevil:chat:";
const CHAT_PRIVACY_ACK    = "findevil:chat:privacy-ack";
const CHAT_PREFS          = "findevil:chat:prefs";

function currentChatScope() {
  // hash like #/cases/INC-2026-0003?tab=findings → caseID = INC-2026-0003
  const m = (window.location.hash || "").match(/^#\/cases\/([^/?]+)/);
  return m ? decodeURIComponent(m[1]) : "global";
}

function loadChatHistory(scope) {
  try {
    const raw = localStorage.getItem(CHAT_STORAGE_PREFIX + scope);
    return raw ? JSON.parse(raw) : [];
  } catch (_) { return []; }
}
function saveChatHistory(scope, msgs) {
  try { localStorage.setItem(CHAT_STORAGE_PREFIX + scope, JSON.stringify(msgs)); }
  catch (_) {}
}
function loadChatPrefs() {
  try { return JSON.parse(localStorage.getItem(CHAT_PREFS) || "{}"); }
  catch (_) { return {}; }
}
function saveChatPrefs(p) {
  try { localStorage.setItem(CHAT_PREFS, JSON.stringify(p)); } catch (_) {}
}

// Minimal markdown-ish rendering: code blocks + inline code. Anything else
// is left as plain text (CSS handles whitespace via white-space: pre-wrap).
function renderMessageHTML(text) {
  // Escape first; then re-introduce <pre><code> and <code> blocks.
  let s = String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  s = s.replace(/```([\s\S]*?)```/g, (_, body) => `<pre><code>${body.trim()}</code></pre>`);
  s = s.replace(/`([^`]+?)`/g, "<code>$1</code>");
  return s;
}

let chatState = {
  open: false,
  sending: false,
  scope: "global",
  msgs: [],
};

function mountChat() {
  // FAB
  const fab = h("button", { class: "chat-fab", id: "chat-fab", title: "FindEvil Assistant" }, "💬");
  fab.onclick = () => toggleChatDrawer();
  document.body.appendChild(fab);

  // Drawer (initially hidden via CSS transform)
  const drawer = h("div", { class: "chat-drawer", id: "chat-drawer" });
  document.body.appendChild(drawer);
  renderChatDrawer(drawer);

  // Esc to close
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape" && chatState.open) toggleChatDrawer();
  });
  // React to hash changes — case context shifts
  window.addEventListener("hashchange", () => {
    if (chatState.open) {
      chatState.scope = currentChatScope();
      chatState.msgs = loadChatHistory(chatState.scope);
      renderChatDrawer(drawer);
    }
  });
}

function toggleChatDrawer() {
  const drawer = $("#chat-drawer");
  chatState.open = !chatState.open;
  if (chatState.open) {
    chatState.scope = currentChatScope();
    chatState.msgs = loadChatHistory(chatState.scope);
    renderChatDrawer(drawer);
    drawer.classList.add("open");
    setTimeout(() => $("#chat-input")?.focus(), 100);
  } else {
    drawer.classList.remove("open");
  }
}

function renderChatDrawer(drawer) {
  const prefs = loadChatPrefs();
  const engine = prefs.engine || "claude-code";
  const model  = prefs.model || "";
  const scope = chatState.scope;
  const ctxLabel = scope === "global"
    ? "context: FindEvil documentation"
    : `context: case ${scope}`;

  drawer.innerHTML = "";
  drawer.appendChild(h("div", { class: "chat-header" }, [
    h("span", { class: "title" }, "FindEvil Assistant"),
    h("span", { class: "ctx" }, ctxLabel),
    h("span", { class: "spacer" }),
    h("button", { class: "close-btn", title: "Close (Esc)", onclick: () => toggleChatDrawer() }, "×"),
  ]));

  drawer.appendChild(h("div", { class: "chat-toolbar" }, [
    h("span", { class: "muted" }, "Engine:"),
    h("select", {
      id: "chat-engine",
      onchange: (ev) => {
        const p = loadChatPrefs(); p.engine = ev.target.value; saveChatPrefs(p);
      },
    }, [
      h("option", { value: "claude-code", ...(engine === "claude-code" ? {selected: "selected"} : {}) }, "claude-code"),
      h("option", { value: "anthropic-api", ...(engine === "anthropic-api" ? {selected: "selected"} : {}) }, "anthropic-api"),
    ]),
    h("input", { id: "chat-model", placeholder: "model (engine default if blank)", value: model,
      style: "max-width:170px; font-size:11px;",
      onchange: (ev) => { const p = loadChatPrefs(); p.model = ev.target.value.trim(); saveChatPrefs(p); }}),
    h("button", { class: "ghost clear-btn", onclick: () => clearChatHistory() }, "Clear"),
  ]));

  const msgArea = h("div", { class: "chat-messages", id: "chat-messages" });
  drawer.appendChild(msgArea);
  redrawChatMessages();

  drawer.appendChild(h("div", { class: "chat-input-row" }, [
    h("textarea", {
      id: "chat-input",
      placeholder: "Ask about FindEvil, or about this case's findings...  (Enter to send, Shift+Enter newline)",
      onkeydown: (ev) => {
        if (ev.key === "Enter" && !ev.shiftKey) {
          ev.preventDefault(); sendChat();
        }
      },
    }),
    h("button", { class: "primary", id: "chat-send", onclick: () => sendChat() }, "Send"),
  ]));
}

function redrawChatMessages() {
  const msgArea = $("#chat-messages");
  if (!msgArea) return;
  msgArea.innerHTML = "";

  if (chatState.msgs.length === 0) {
    const tip = chatState.scope === "global"
      ? "Try: 「FindEvil の使い方を教えて」/ 「Persistence Tactic Agent は何を見ている？」"
      : "Try: 「このケースの最も重要な findings は？」/ 「Kill Chain を解説して」";
    msgArea.appendChild(h("div", { class: "chat-empty" }, tip));
  }

  for (const m of chatState.msgs) {
    const initial = m.role === "user" ? "U" : "A";
    const bubble = h("div", { class: "bubble", html: renderMessageHTML(m.content) });
    const wrap = h("div", { class: "chat-msg " + m.role }, [
      h("div", { class: "avatar" }, initial),
      bubble,
    ]);
    if (m.meta) {
      bubble.appendChild(h("div", { class: "meta" }, m.meta));
    }
    msgArea.appendChild(wrap);
  }

  if (chatState.sending) {
    msgArea.appendChild(h("div", { class: "chat-loading" }, [
      h("span", { class: "spinner" }), "thinking…",
    ]));
  }
  msgArea.scrollTop = msgArea.scrollHeight;
}

function clearChatHistory() {
  if (!confirm("Clear chat history for this scope?")) return;
  chatState.msgs = [];
  saveChatHistory(chatState.scope, []);
  redrawChatMessages();
}

async function sendChat() {
  if (chatState.sending) return;
  const input = $("#chat-input");
  const text = (input?.value || "").trim();
  if (!text) return;

  // First-send privacy ack — show one warning per browser, persist via localStorage.
  if (!localStorage.getItem(CHAT_PRIVACY_ACK)) {
    const ok = confirm(
      "FindEvil Assistant について:\n\n" +
      "あなたのメッセージと現在のケースのサマリ (synthesis 結果) が、選択したエンジン" +
      " (claude-code / Anthropic API) に送信されます。\n\n" +
      "法的に機密性の高いケースで使用する場合は、データ転送の許諾を得てから続行してください。\n\n" +
      "OK で続行(以後この警告は表示されません)。"
    );
    if (!ok) return;
    localStorage.setItem(CHAT_PRIVACY_ACK, "1");
  }

  const prefs = loadChatPrefs();
  const engine = prefs.engine || "claude-code";
  const model  = prefs.model || "";

  chatState.msgs.push({ role: "user", content: text });
  saveChatHistory(chatState.scope, chatState.msgs);
  input.value = "";
  chatState.sending = true;
  redrawChatMessages();

  try {
    const body = {
      messages: chatState.msgs.map((m) => ({ role: m.role, content: m.content })),
      engine, model,
    };
    if (chatState.scope !== "global") body.case_id = chatState.scope;

    const resp = await api("POST", "/api/chat", body);
    chatState.msgs.push({
      role: "assistant",
      content: resp.content,
      meta: `${resp.engine}${resp.model ? " · " + resp.model : ""} · ` +
            `${resp.input_tokens}→${resp.output_tokens} tok · ` +
            `${(resp.duration_ms/1000).toFixed(1)}s` +
            (resp.cost_usd ? ` · $${resp.cost_usd.toFixed(4)}` : ""),
    });
    saveChatHistory(chatState.scope, chatState.msgs);
  } catch (e) {
    chatState.msgs.push({
      role: "assistant",
      content: "**Error**: " + (e.message || String(e)),
      meta: "request failed",
    });
    saveChatHistory(chatState.scope, chatState.msgs);
  } finally {
    chatState.sending = false;
    redrawChatMessages();
  }
}

// Mount the FAB after the rest of the SPA initialises.
window.addEventListener("DOMContentLoaded", () => {
  // Wait one tick so the main DOMContentLoaded handler (router) finishes first.
  setTimeout(mountChat, 0);
});
