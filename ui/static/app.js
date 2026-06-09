/* TLVB Examiner Portal — vanilla JS SPA.
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
  return localStorage.getItem("tlvb_locale") || "ja";
}
function setLocale(lang) {
  localStorage.setItem("tlvb_locale", lang);
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
  // Defensive child append: accept Node, string, number, or array (nested
  // one level). Anything else is logged and skipped — beats throwing
  // "parameter 1 is not of type 'Node'" half-way through a render.
  const appendOne = (c) => {
    if (c == null || c === false) return;
    if (typeof c === "string" || typeof c === "number" || typeof c === "boolean") {
      el.appendChild(document.createTextNode(String(c)));
      return;
    }
    if (Array.isArray(c)) {
      for (const cc of c) appendOne(cc);
      return;
    }
    if (c instanceof Node) {
      el.appendChild(c);
      return;
    }
    if (typeof console !== "undefined" && console.warn) {
      console.warn("h(): skipping non-Node child", c, "in <" + tag + ">");
    }
  };
  appendOne(children);
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
    let busy = false;
    if (ct.includes("application/json")) {
      try { const j = await r.json(); if (j.error) msg = j.error; if (j.busy) busy = true; } catch (_) {}
    } else {
      try { msg = (await r.text()).slice(0, 200) || msg; } catch (_) {}
    }
    const err = new Error(msg);
    // 503 + busy:true — the case DB is held by a running job (Parse / mutation),
    // not a real failure. Callers render a "processing" notice instead of an error.
    if (busy || r.status === 503) err.busy = true;
    throw err;
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

// Last-known case-detail payload per case id. When a job holds the DB, the
// case route falls back to this so the page (tabs, progress, disk-backed tabs)
// keeps rendering instead of collapsing to a full-page busy notice.
let caseDetailCache = {};

// busyNotice renders the "the DB is held by a running job" state. It exists so
// a blocked read shows an explicit "processing — temporarily unavailable" card
// (with a retry) rather than a spinner that looks frozen. onRetry re-runs the
// current view; it auto-clears once the job releases the DB.
function busyNotice(onRetry) {
  // Auto-refresh so the view self-heals when the job releases the DB — the user
  // never has to sit on a dead-end. A single timer per render forms one chain.
  if (onRetry) setTimeout(onRetry, 3000);
  return h("div", { class: "card busy-notice" }, [
    h("h2", {}, "⏳ 処理中のため表示できません"),
    h("p", { class: "muted" },
      "別の処理 (Parse など) がケースのデータベースを使用中のため、この表示は一時的に参照できません。" +
      "フリーズではありません — 完了すると自動で表示されます。"),
    h("p", { class: "muted" },
      "Temporarily unavailable: a running job (e.g. Parse) holds the case database. Auto-refreshing…"),
    h("div", { class: "row", style: "gap: 8px; margin-top: 8px;" }, [
      onRetry ? h("button", { class: "ghost", onclick: onRetry }, "今すぐ再読み込み / Retry") : null,
      h("button", { class: "ghost", onclick: () => navigate("/") }, "← Dashboard へ戻る"),
    ]),
  ]);
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
  let cases;
  try {
    cases = await api("GET", "/api/cases");
  } catch (e) {
    // The case list reads cases.duckdb, which a Parse holds exclusively. Show
    // the auto-refreshing notice instead of an error so the Dashboard recovers.
    if (e && e.busy) {
      const app = $("#app");
      app.innerHTML = "";
      app.appendChild(busyNotice(() => dispatch()));
      return;
    }
    throw e;
  }
  const app = $("#app");
  app.innerHTML = "";

  // Global tools row — links to non-case-scoped views (Rule Library).
  app.appendChild(h("div", { class: "row", style: "justify-content: flex-end; margin-bottom: 8px;" }, [
    h("a", { class: "ghost", href: "#/rules", style: "padding: 6px 12px; border-radius: 3px;" },
      "📚 Rule Library"),
  ]));

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

// ============================================================================
// Rule Library (global, not case-scoped) — rules.duckdb inspection.
// Build coverage snapshot + filterable rule_sql_cache list + Tier 1B
// skill_sql_cache (learned lenses). Filter state lives in the URL query
// (source / state / q / offset) so navigation re-renders consistently.
// ============================================================================
route(/^\/rules$/, async ({ params }) => {
  setCrumbs([{ label: "Dashboard", href: "/" }, { label: "Rule Library" }]);
  setMeta("");
  const app = $("#app");
  app.innerHTML = "";

  const source = params.source || "";
  const state = params.state || "";
  const q = params.q || "";
  const limit = 100;
  const offset = Math.max(0, parseInt(params.offset || "0", 10) || 0);

  // Merge current filters with overrides and navigate (offset resets to 0
  // unless explicitly overridden).
  const goRules = (ov) => {
    const cur = { source, state, q, offset: 0, ...ov };
    const qs = new URLSearchParams();
    if (cur.source) qs.set("source", cur.source);
    if (cur.state) qs.set("state", cur.state);
    if (cur.q) qs.set("q", cur.q);
    if (cur.offset) qs.set("offset", String(cur.offset));
    navigate("/rules" + (qs.toString() ? "?" + qs.toString() : ""));
  };

  // ---- build-coverage summary ----
  const sumCard = h("div", { class: "card" }, [h("h2", {}, "ビルドカバレッジ")]);
  app.appendChild(sumCard);
  let summary = { available: false, rules: { by_state: {}, by_source: [] }, skills: {} };
  try { summary = await api("GET", "/api/rules/summary"); } catch (e) { /* shown below */ }

  if (!summary.available) {
    sumCard.appendChild(h("div", { class: "empty" },
      "rules.duckdb が見つかりません。`tlvb rules build` でルール SQL キャッシュを生成してください。"));
  } else {
    const r = summary.rules || { by_state: {}, by_source: [] };
    const bs = r.by_state || {};
    sumCard.appendChild(h("div", { class: "badges" }, [
      h("span", { class: "badge ok" }, `built ${bs.built || 0}`),
      h("span", { class: "badge pending" }, `pending ${bs.pending || 0}`),
      h("span", { class: "badge err" }, `failed ${bs.failed || 0}`),
      h("span", { class: "badge tactic" }, `total ${r.total || 0}`),
    ]));
    const tbl = h("table", { class: "rules-table" }, [
      h("tr", {}, ["source", "built", "pending", "failed", "total"].map((x) => h("th", {}, x))),
      ...(r.by_source || []).map((sc) => h("tr", {}, [
        h("td", {}, sc.source),
        h("td", {}, String(sc.built)),
        h("td", {}, String(sc.pending)),
        h("td", { class: sc.failed > 0 ? "cell-warn" : "" }, String(sc.failed)),
        h("td", {}, String(sc.total)),
      ])),
    ]);
    sumCard.appendChild(tbl);
    const sk = summary.skills || {};
    sumCard.appendChild(h("div", { class: "muted", style: "margin-top: 10px;" },
      `Tier 1B skill cache: canonical ${sk.canonical || 0} / candidate ${sk.candidate || 0} (total ${sk.total || 0})`));
  }

  if (!summary.available) return;

  // ---- filter controls ----
  const sources = ["", ...((summary.rules && summary.rules.by_source) || []).map((s) => s.source)];
  const states = ["", "built", "pending", "failed"];
  const sourceSel = selectEl(sources, source, (v) => goRules({ source: v }), (x) => x || "(all sources)");
  const stateSel = selectEl(states, state, (v) => goRules({ state: v }), (x) => x || "(all states)");
  const searchInput = h("input", {
    placeholder: "search id / title / SQL / technique", value: q,
    style: "flex: 1; min-width: 200px;",
    onkeydown: (e) => { if (e.key === "Enter") goRules({ q: e.target.value.trim() }); },
  });
  const filterCard = h("div", { class: "card" }, [
    h("div", { class: "row", style: "gap: 8px; align-items: center; flex-wrap: wrap;" }, [
      h("label", { class: "muted" }, "source"), sourceSel,
      h("label", { class: "muted" }, "state"), stateSel,
      searchInput,
      h("button", { onclick: () => goRules({ q: searchInput.value.trim() }) }, "検索"),
      (source || state || q)
        ? h("button", { class: "ghost", onclick: () => navigate("/rules") }, "クリア")
        : null,
    ]),
  ]);
  app.appendChild(filterCard);

  // ---- rule list ----
  const listCard = h("div", { class: "card" }, [h("h2", {}, "ルール一覧")]);
  app.appendChild(listCard);
  const qs = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (source) qs.set("source", source);
  if (state) qs.set("state", state);
  if (q) qs.set("q", q);
  const resp = await api("GET", "/api/rules?" + qs.toString());
  const rows = resp.rows || [];
  const total = resp.total || 0;
  const shownFrom = total === 0 ? 0 : offset + 1;
  const shownTo = offset + rows.length;

  listCard.appendChild(h("div", { class: "muted", style: "margin-bottom: 8px;" },
    `${shownFrom}–${shownTo} / ${total}`));

  if (rows.length === 0) {
    listCard.appendChild(h("div", { class: "empty" }, "該当ルールなし"));
  } else {
    rows.forEach((rr) => listCard.appendChild(ruleDetailsEl(rr)));
    // pagination
    const pager = h("div", { class: "row", style: "gap: 8px; margin-top: 10px;" }, [
      offset > 0
        ? h("button", { class: "ghost", onclick: () => goRules({ offset: Math.max(0, offset - limit) }) }, "← 前")
        : null,
      shownTo < total
        ? h("button", { class: "ghost", onclick: () => goRules({ offset: offset + limit }) }, "次 →")
        : null,
    ]);
    listCard.appendChild(pager);
  }

  // ---- Tier 1B skill cache (learned lenses) ----
  const skillCard = h("div", { class: "card" }, [h("h2", {}, "Tier 1B 学習済みクエリ (skill cache)")]);
  app.appendChild(skillCard);
  let skillResp = { rows: [] };
  try { skillResp = await api("GET", "/api/rules/skills"); } catch (e) { /* ignore */ }
  const skillRows = skillResp.rows || [];
  if (skillRows.length === 0) {
    skillCard.appendChild(h("div", { class: "empty" },
      "学習済みクエリはまだありません (analyze --tier 1b を実 LLM で実行すると蓄積されます)。"));
  } else {
    skillRows.forEach((sr) => skillCard.appendChild(skillDetailsEl(sr)));
  }
});

// selectEl builds a <select> that calls onChange(value) on change.
function selectEl(options, current, onChange, labelFn) {
  const sel = h("select", { onchange: (e) => onChange(e.target.value) });
  options.forEach((opt) => {
    const o = h("option", { value: opt }, labelFn ? labelFn(opt) : opt);
    if (opt === current) o.selected = true;
    sel.appendChild(o);
  });
  return sel;
}

// ruleDetailsEl renders one rule_sql_cache row as a collapsible <details>.
function ruleDetailsEl(rr) {
  const lvl = (rr.level || "").toLowerCase();
  const sev = lvl === "informational" ? "info" : (lvl || "info");
  const head = h("summary", { class: "rule-summary" }, [
    h("span", { class: "badge state-rule-" + rr.state }, rr.state),
    h("span", { class: "badge source-rule" }, rr.rule_source),
    rr.level ? h("span", { class: "badge sev-" + sev }, rr.level) : null,
    h("span", { class: "rule-title" }, rr.title || rr.rule_id),
  ]);
  const metaBits = [];
  if (rr.mitre_techniques && rr.mitre_techniques.length)
    metaBits.push("technique: " + rr.mitre_techniques.join(", "));
  if (rr.prefilter_artifacts) metaBits.push("prefilter: " + rr.prefilter_artifacts);
  if (rr.generated_at) metaBits.push("built: " + rr.generated_at);
  metaBits.push("id: " + rr.rule_id);
  const detail = h("div", { class: "rule-detail" }, [
    h("div", { class: "muted", style: "margin-bottom: 6px; font-size: 12px;" }, metaBits.join("  ·  ")),
    rr.sql ? h("pre", { class: "rule-sql" }, rr.sql) : h("div", { class: "muted" }, "(no SQL — not built)"),
    rr.error_message ? h("pre", { class: "rule-sql err" }, rr.error_message) : null,
  ]);
  return h("details", { class: "rule-item" }, [head, detail]);
}

// skillDetailsEl renders one skill_sql_cache row.
function skillDetailsEl(sr) {
  const head = h("summary", { class: "rule-summary" }, [
    h("span", { class: "badge " + (sr.state === "canonical" ? "approved" : "pending") }, sr.state),
    h("span", { class: "badge tactic" }, "hits " + (sr.hit_count || 0)),
    h("span", { class: "rule-title" }, sr.intent || sr.skill),
  ]);
  const metaBits = [];
  if (sr.skill) metaBits.push("skill: " + sr.skill);
  if (sr.origin_case) metaBits.push("origin: " + sr.origin_case);
  if (sr.last_used_case) metaBits.push("last used: " + sr.last_used_case);
  if (sr.generated_at) metaBits.push("added: " + sr.generated_at);
  const detail = h("div", { class: "rule-detail" }, [
    h("div", { class: "muted", style: "margin-bottom: 6px; font-size: 12px;" }, metaBits.join("  ·  ")),
    sr.sql ? h("pre", { class: "rule-sql" }, sr.sql) : null,
  ]);
  return h("details", { class: "rule-item" }, [head, detail]);
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

  let detail;
  let staleFromCache = false;
  try {
    detail = await api("GET", `/api/cases/${encodeURIComponent(caseID)}`);
    caseDetailCache[caseID] = detail;
  } catch (e) {
    if (e && e.busy && caseDetailCache[caseID]) {
      // A job holds the DB, but we have last-known case metadata: render the
      // page anyway so the tab bar, pipeline progress and disk-backed tabs
      // (Findings/Report/…) stay usable. DB-backed tabs show their own notice.
      // Mark it stale so the header flags that counts are pre-job values.
      detail = caseDetailCache[caseID];
      staleFromCache = true;
    } else if (e && e.busy) {
      // No cached metadata (first visit during a job) — minimal notice with a
      // Dashboard escape + auto-refresh, instead of a full-page dead-end.
      const app = $("#app");
      app.innerHTML = "";
      app.appendChild(busyNotice(() => dispatch()));
      return;
    } else {
      throw e;
    }
  }
  setMeta(`evidence=${detail.case.evidence_count} events=${detail.case.unified_event_rows}` +
    (staleFromCache ? " ⏳(処理開始前の値)" : ""));

  const app = $("#app");
  app.innerHTML = "";

  // ---- header card
  const c = detail.case;
  const headerCard = h("div", { class: "card" }, [
    h("div", { class: "row", style: "align-items: center;" }, [
      h("div", { style: "flex: 1;" }, [
        h("h1", {}, c.case_id + " — " + c.name),
        staleFromCache ? h("span", {
          class: "badge warn",
          title: "別の処理 (Parse 等) が DB を使用中のため、件数などはジョブ開始前の値です。進捗バーはライブ。完了すると自動で更新されます。",
        }, "⏳ 処理中（表示はジョブ開始前の値）") : null,
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

  try {
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
  } catch (e) {
    // A DB-backed tab (e.g. Events) can't read while a job holds the DB. Show
    // the "processing" notice in the pane — the tab bar and pipeline progress
    // above it stay live. Findings/Report read from disk and never hit this.
    if (e && e.busy) {
      tabPane.innerHTML = "";
      tabPane.appendChild(busyNotice(() => dispatch()));
    } else {
      throw e;
    }
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
  } else if (st.state === "succeeded" || st.state === "partial") {
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
  // Partial = the step completed and produced usable output, but some
  // sub-units failed (e.g. some artifacts didn't parse). A warning, not a
  // red FAIL — the detail rides in st.message.
  if (st.state === "partial")   return "PARTIAL · " + (st.message || "一部のアーティファクトのパースでエラー");
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
      "available. Tier 1A (cached signature SQL) still runs fine without an " +
      "LLM — only the optional Tier 1B anomaly_hunter pass needs one. " +
      "To enable it, install Claude Code CLI (`npm i -g @anthropic-ai/claude-code` + " +
      "`claude` once to /login), or `export ANTHROPIC_API_KEY=...` and " +
      "restart the server."),
  ]) : null;
  const llmInfo = llm.ok ? h("p", { class: "muted", style: "font-size: 11px; margin-top: 0;" },
    "✓ LLM access OK — " +
    (llm.claude_cli ? `claude CLI (${llm.claude_version || "version unknown"})` : "") +
    (llm.claude_cli && llm.api_key_set ? " + " : "") +
    (llm.api_key_set ? "ANTHROPIC_API_KEY set" : "")) : null;

  const close = modal([
    h("h3", {}, "Analyze — Tier 1A (signature SQL) + Tier 1B (optional)"),
    warn,
    llmInfo,
    h("p", { class: "muted" },
      "Tier 1A always runs: cached signature SQL (Sigma / Hayabusa / STIX / custom / LOLBAS) " +
      "against this case — no LLM, no cost. Tier 1B (anomaly_hunter) is an optional LLM pass."),
    h("div", { class: "form-row" }, [h("label", {}, "Also run Tier 1B (anomaly_hunter, LLM)"),
      h("input", { id: "a_anomaly", type: "checkbox" })]),
    h("div", { class: "form-row" }, [h("label", {}, "Tier 1B model"),
      h("input", { id: "a_model", placeholder: "(claude CLI default)" })]),
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
    h("h3", {}, "Run Tier 2 (Timeline Analysis)"),
    h("div", { class: "form-row" }, [h("label", {}, "Active search"),
      h("input", { id: "s_active", type: "checkbox" })]),
    h("p", { class: "muted" }, "Tier 2 clusters Tier 1 findings and analyses each cluster's ±N-min timeline with an LLM. Active search adds a hypothesis-driven wide-range SQL pass per cluster (slower, more thorough)."),
    h("div", { class: "actions" }, [
      h("button", { class: "ghost", onclick: () => close() }, "Cancel"),
      h("button", { class: "primary", onclick: async () => {
        try {
          await api("POST", `/api/cases/${encodeURIComponent(caseID)}/synthesize`, {
            active_search: $("#s_active").checked,
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
      { active_search: false });
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
    // Partial is a terminal success for flow control: usable output exists,
    // so the chain (e.g. autopilot parse → analyze) proceeds. The warning is
    // already surfaced in the per-step status block.
    if (st.state === "partial")  return st;
    if (st.state === "failed")   throw new Error(`${kind} failed: ${st.error || st.message || "(no detail)"}`);
    if (st.state === "canceled") throw new Error(`${kind} canceled by examiner`);
    // idle is fine briefly right after POST; running is the expected hot state.
  }
}

// ============================================================================
// Review Gate 1A — Findings tab
// ============================================================================
// Renders the unified Tier 1A (by-rule) + Tier 1B (by-skill) finding list.
// Backend already returns severity-desc + pending-first order; the front-end
// groups by MITRE tactic and exposes per-row + per-cluster bulk approve.
//
// Per-pane state (pane._findings):
//   filter:        all | pending | reviewed | auto-approved
//   sourceFilter:  all | tier1a | tier1b
//   selected:      Set of finding_ids the user has ticked
async function renderFindings(pane, caseID) {
  pane.innerHTML = `<div class="empty"><span class="spinner"></span>loading findings…</div>`;
  let findings;
  try { findings = await api("GET", `/api/cases/${encodeURIComponent(caseID)}/findings`); }
  catch (e) { pane.innerHTML = `<div class="empty">No findings yet (run Analyze first).</div>`; return; }
  if (!findings || findings.length === 0) {
    pane.innerHTML = `<div class="empty">No findings yet (run Analyze first).</div>`; return;
  }

  // Group by primary MITRE tactic; "uncategorized" for findings with no tactic.
  const groups = new Map();
  for (const f of findings) {
    const tactic = (f.mitre_tactics && f.mitre_tactics[0]) || "uncategorized";
    if (!groups.has(tactic)) groups.set(tactic, { tactic, findings: [] });
    groups.get(tactic).findings.push(f);
  }

  pane._findings = {
    caseID,
    findingsById: Object.fromEntries(findings.map((f) => [f.finding_id, f])),
    selected: new Set(),
    filter: "all",         // all | pending | reviewed | auto-approved
    sourceFilter: "all",   // all | tier1a | tier1b
  };

  pane.innerHTML = "";

  const toolbar = h("div", { class: "findings-toolbar" });
  pane.appendChild(toolbar);
  refreshFindingsToolbar(pane);

  // Tactic groups in the order they first appear (backend sort already
  // surfaces highest-severity tactic first because findings are sorted
  // severity-desc before grouping).
  const groupOrder = [...groups.values()];
  for (const g of groupOrder) {
    const list = h("div", { class: "findings hidden" }); // collapsed by default
    const visibleSubset = g.findings.filter((f) =>
      findingMatchesFilter(f, pane._findings.filter, pane._findings.sourceFilter));
    const sevSummary = severitySummary(g.findings);
    const header = h("div", { class: "tactic-header" }, [
      h("span", { class: "tactic-toggle" }, "▸"),
      h("span", { class: "name" }, g.tactic),
      h("span", { class: "spacer" }),
      ...sevSummary,
      h("span", { class: "count" }, g.findings.length + " findings"),
    ]);
    header.onclick = (ev) => {
      if (ev.target.tagName === "INPUT" || ev.target.tagName === "BUTTON") return;
      const collapsed = list.classList.toggle("hidden");
      header.querySelector(".tactic-toggle").textContent = collapsed ? "▸" : "▾";
    };

    const groupCheck = h("input", {
      type: "checkbox",
      class: "tactic-select-all",
      title: "select every visible finding in this tactic",
      onclick: (ev) => {
        ev.stopPropagation();
        const checked = ev.target.checked;
        for (const f of g.findings) {
          if (!findingMatchesFilter(f, pane._findings.filter, pane._findings.sourceFilter)) continue;
          if (checked) pane._findings.selected.add(f.finding_id);
          else pane._findings.selected.delete(f.finding_id);
          const cb = pane.querySelector(`input.row-select[data-fid="${cssEscape(f.finding_id)}"]`);
          if (cb) cb.checked = checked;
        }
        refreshFindingsToolbar(pane);
      },
    });
    header.insertBefore(groupCheck, header.firstChild);

    // Per-cluster bulk-approve button (Review Gate 1A — DESIGN §6.5).
    const bulkApprove = h("button", {
      class: "ghost",
      style: "padding: 2px 8px; font-size: 11px; margin-left: 8px;",
      title: "approve every pending finding in this tactic",
      onclick: async (ev) => {
        ev.stopPropagation();
        const pendingIds = g.findings
          .filter((f) => !f.approved && !f.rejected)
          .map((f) => f.finding_id);
        if (pendingIds.length === 0) return;
        if (!confirm(`Approve ${pendingIds.length} pending finding(s) in tactic "${g.tactic}"?`)) return;
        await runBulk(pane, pendingIds, "approve", "");
      },
    }, "Approve cluster");
    header.appendChild(bulkApprove);

    g.findings.forEach((f) => list.appendChild(findingRow(caseID, f, pane)));

    const group = h("div", { class: "tactic-group" }, [header, list]);
    pane.appendChild(group);
  }
}

// severitySummary renders compact severity-count chips for the tactic header.
function severitySummary(findings) {
  const counts = {critical:0, high:0, medium:0, low:0, info:0};
  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity]++;
  }
  const out = [];
  for (const sev of ["critical","high","medium","low","info"]) {
    if (counts[sev] === 0) continue;
    out.push(h("span", { class: "badge sev-" + sev, style: "margin-right: 4px;" },
      sev + ": " + counts[sev]));
  }
  return out;
}

function findingMatchesFilter(f, mode, sourceMode) {
  if (sourceMode && sourceMode !== "all" && f.source !== sourceMode) return false;
  if (mode === "pending")        return !f.approved && !f.rejected;
  if (mode === "reviewed")       return (f.approved || f.rejected) && !f.auto_approved;
  if (mode === "auto-approved")  return f.auto_approved;
  return true; // "all"
}

function refreshFindingsToolbar(pane) {
  const state = pane._findings;
  const findings = Object.values(state.findingsById);
  const total = findings.length;
  const approved = findings.filter((f) => f.approved && !f.auto_approved).length;
  const autoApproved = findings.filter((f) => f.auto_approved).length;
  const rejected = findings.filter((f) => f.rejected).length;
  const pending = findings.filter((f) => !f.approved && !f.rejected).length;
  const selectedCount = state.selected.size;
  const visibleCount = findings.filter((f) =>
    findingMatchesFilter(f, state.filter, state.sourceFilter)).length;

  const toolbar = pane.querySelector(".findings-toolbar");
  toolbar.innerHTML = "";

  // Filter row 1: review state.
  const filterRow = h("div", { class: "row", style: "gap: 6px; align-items: center;" }, [
    h("span", { class: "muted", style: "font-size: 11px;" }, "State:"),
    ...["all","pending","reviewed","auto-approved"].map((mode) => {
      return h("button", {
        class: state.filter === mode ? "primary" : "ghost",
        style: "padding: 4px 10px; font-size: 11px;",
        onclick: () => {
          state.filter = mode;
          applyVisibilityFilter(pane);
          refreshFindingsToolbar(pane);
        },
      }, mode);
    }),
    h("span", { class: "spacer" }),
    h("span", { class: "muted", style: "font-size: 11px;" },
      `Total ${total} · pending ${pending} · reviewed ${approved} · auto ${autoApproved} · rejected ${rejected}` +
      (state.filter !== "all" || state.sourceFilter !== "all" ? ` · showing ${visibleCount}` : "")),
  ]);
  toolbar.appendChild(filterRow);

  // Filter row 2: source (Tier 1A vs 1B).
  const sourceRow = h("div", { class: "row", style: "gap: 6px; align-items: center; margin-top: 4px;" }, [
    h("span", { class: "muted", style: "font-size: 11px;" }, "Source:"),
    ...[["all","All"],["tier1a","Tier 1A (rules)"],["tier1b","Tier 1B (skills)"]].map(([mode,label]) => {
      return h("button", {
        class: state.sourceFilter === mode ? "primary" : "ghost",
        style: "padding: 4px 10px; font-size: 11px;",
        onclick: () => {
          state.sourceFilter = mode;
          applyVisibilityFilter(pane);
          refreshFindingsToolbar(pane);
        },
      }, label);
    }),
  ]);
  toolbar.appendChild(sourceRow);

  // Bulk action row.
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
    h("button", {
      class: "primary",
      style: "padding: 4px 10px; font-size: 11px;",
      title: "Approve every finding currently visible (respects the filters above)",
      disabled: visibleCount === 0 ? "disabled" : null,
      onclick: async () => {
        if (!confirm(`Approve all ${visibleCount} visible finding(s)?`)) return;
        const ids = findings
          .filter((f) => findingMatchesFilter(f, state.filter, state.sourceFilter))
          .map((f) => f.finding_id);
        await runBulk(pane, ids, "approve", "");
      },
    }, `Approve all visible (${visibleCount})`),
  ]);
  toolbar.appendChild(bulkRow);
}

// applyVisibilityFilter toggles per-row visibility based on the current
// state/source filters without rebuilding the DOM (preserves scroll).
function applyVisibilityFilter(pane) {
  const state = pane._findings;
  for (const f of Object.values(state.findingsById)) {
    const row = pane.querySelector(`.finding[data-fid="${cssEscape(f.finding_id)}"]`);
    if (!row) continue;
    const visible = findingMatchesFilter(f, state.filter, state.sourceFilter);
    row.classList.toggle("filtered-out", !visible);
  }
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
    // Update local state + DOM rows in place — no scroll jump.
    const now = new Date().toISOString();
    for (const id of ids) {
      const f = state.findingsById[id];
      if (!f) continue;
      if (action === "approve") {
        f.approved = true; f.rejected = false; f.reject_reason = "";
        f.auto_approved = false; f.approved_by = "examiner-web";
        f.reviewed_at = now; f.reviewed_by = "examiner-web";
      } else if (action === "reject") {
        f.approved = false; f.rejected = true; f.reject_reason = reason || "";
        f.auto_approved = false; f.approved_by = "";
        f.reviewed_at = now; f.reviewed_by = "examiner-web";
      } else if (action === "reset") {
        // Restore severity-based default — mirrors AutoApproveByLevel in Go.
        const autoOK = ["medium","low","info",""].includes(f.severity || "");
        f.approved = autoOK; f.rejected = false; f.reject_reason = "";
        f.auto_approved = autoOK;
        f.approved_by = autoOK ? "auto:severity-rule" : "";
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
// doesn't reset.
function updateFindingRowDOM(pane, f) {
  const row = pane.querySelector(`.finding[data-fid="${cssEscape(f.finding_id)}"]`);
  if (!row) return;
  row.className = findingRowClass(f, pane);
  const stateBadge = row.querySelector(".state-badge");
  if (stateBadge) {
    const s = reviewStateLabel(f);
    stateBadge.className = "badge state-badge " + s.cls;
    stateBadge.textContent = s.label;
  }
  const actions = row.querySelector(".actions");
  if (actions) {
    actions.innerHTML = "";
    rebuildActionButtons(pane, f, actions);
  }
}

function findingRowClass(f, pane) {
  let cls = "finding";
  if (f.approved && f.auto_approved) cls += " auto-approved";
  else if (f.approved) cls += " approved";
  else if (f.rejected) cls += " rejected";
  if (!findingMatchesFilter(f, pane._findings.filter, pane._findings.sourceFilter)) {
    cls += " filtered-out";
  }
  return cls;
}

function reviewStateLabel(f) {
  if (f.rejected)             return { cls: "rejected",      label: "rejected" };
  if (f.approved && f.auto_approved) return { cls: "auto-approved", label: "auto" };
  if (f.approved)             return { cls: "approved",      label: "approved" };
  return { cls: "pending", label: "pending" };
}

function rebuildActionButtons(pane, f, actions) {
  if (!f.approved && !f.rejected) {
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
    const reviewedBy = f.auto_approved ? (f.approved_by || "auto:severity-rule") : (f.reviewed_by || "?");
    const when = f.auto_approved ? "(severity default)" : fmtTS(f.reviewed_at);
    actions.appendChild(h("span", { class: "muted" },
      "Reviewed by " + reviewedBy + " · " + when +
      (f.reject_reason ? " · reason: " + f.reject_reason : "")));
    actions.appendChild(h("button", {
      class: "ghost",
      style: "margin-left: 8px;",
      title: "clear examiner decision and restore severity default",
      onclick: () => runBulk(pane, [f.finding_id], "reset", ""),
    }, "Reset"));
  }
}

function findingRow(caseID, f, pane) {
  const row = h("div", {
    class: findingRowClass(f, pane),
    "data-fid": f.finding_id,
  });
  const sev = f.severity || "info";
  const sourceLabel = f.source === "tier1b"
    ? "1B/" + (f.rule_id || "skill")
    : "1A/" + (f.rule_source || "rule");
  const stateLbl = reviewStateLabel(f);

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
    h("span", { class: "badge sev-" + sev }, sev),
    h("span", { class: "badge source-" + f.source, title: f.rule_id || "" }, sourceLabel),
    ...(f.confidence
      ? [h("span", {
          class: "badge conf-" + f.confidence,
          title: "provenance: " + (f.provenance || ""),
        }, f.confidence)]
      : []),
    h("span", { class: "finding-title" }, f.title || f.rule_id || "(untitled)"),
    h("span", { class: "spacer" }),
    ...(f.mitre_techniques || []).slice(0, 3).map((t) =>
      h("a", {
        class: "technique-id",
        href: "https://attack.mitre.org/techniques/" + t.replace(/\./g, "/"),
        target: "_blank",
        rel: "noopener",
        onclick: (ev) => ev.stopPropagation(),
      }, t)
    ),
    h("span", { class: "badge state-badge " + stateLbl.cls }, stateLbl.label),
  ]);
  row.appendChild(headerLine);

  if (f.description) row.appendChild(h("div", { class: "reasoning" }, f.description));

  // Sub-line: lens (1B) / source path / match_count.
  const subLine = h("div", { class: "muted", style: "font-size: 11px; margin-top: 4px;" }, [
    f.lens ? "lens=" + f.lens + " · " : "",
    "matches=" + (f.match_count || 0) + (f.truncated ? "+" : ""),
    f.source_path ? " · " + f.source_path : "",
    "  ·  " + f.finding_id,
  ].filter(Boolean).join(""));
  row.appendChild(subLine);

  // Evidence preview — backend returns up to 3 preview rows.
  const evList = h("div", { class: "evidence-list hidden" });
  const evItems = [];
  (f.evidence_preview || []).forEach((ev) => {
    const item = h("div", { class: "evidence-item" });
    item.appendChild(h("div", { class: "evidence-head" }, [
      h("span", { class: "source" }, (ev.artifact_id || "?") + " "),
      h("span", { class: "audit-id" }, ev.audit_id),
      ev.event_type ? h("span", { class: "muted", style: "margin-left: 6px;" }, ev.event_type) : "",
      ev.ts_utc ? h("span", { class: "muted", style: "margin-left: 6px;" }, fmtTS(ev.ts_utc)) : "",
    ]));
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
  const previewCount = (f.evidence_preview || []).length;
  const matchCount = f.match_count || 0;
  const toggleLabel = previewCount < matchCount
    ? `▸ ${previewCount} preview rows (of ${matchCount}${f.truncated ? "+" : ""})`
    : `▸ ${previewCount} evidence rows`;
  const toggle = h("div", { class: "evidence-toggle" }, toggleLabel);
  toggle.onclick = () => {
    const willOpen = evList.classList.contains("hidden");
    evList.classList.toggle("hidden");
    toggle.textContent = (willOpen ? "▾ " : "▸ ") + toggleLabel.slice(2);
    if (willOpen) loadEvidencePayloads();
  };
  row.appendChild(toggle);
  row.appendChild(evList);

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
    h("a", { href: `/api/cases/${encodeURIComponent(caseID)}/report/csv/ioc`, download: "ioc.csv" },
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
    h("a", { href: `/api/cases/${encodeURIComponent(caseID)}/report/csv/ioc`, download: "ioc.csv" },
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
    if (e.detail) summary.push(e.detail); // agent sub-kind, e.g. cluster_analysis
    if (e.artifact_id) summary.push("artifact=" + e.artifact_id);
    if (e.cluster_id != null && e.cluster_id !== 0) summary.push("cluster=" + e.cluster_id);
    if (e.attempt) summary.push("attempt=" + e.attempt);
    if (e.outcome) summary.push("outcome=" + e.outcome);
    if (e.rule_id) summary.push("rule=" + e.rule_id);
    if (e.rule_source) summary.push("src=" + e.rule_source);
    if (e.row_count != null) summary.push("rows=" + e.row_count);
    if (e.duration_seconds != null) summary.push("dur=" + e.duration_seconds.toFixed(2) + "s");
    if (e.success != null) summary.push("ok=" + e.success);
    if (e.model) summary.push("model=" + e.model);
    if (e.input_tokens || e.output_tokens) summary.push("tok=" + (e.input_tokens || 0) + "/" + (e.output_tokens || 0));
    if (e.cost_usd) summary.push("$" + e.cost_usd.toFixed(4));
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

// mergeSummaryIntoPhaseResults promotes idle phases to "succeeded" when
// their on-disk artefacts indicate the step previously completed (parse
// rows in cases.duckdb, finding files, synthesis.json, reports/). The
// message prefix "persisted · " distinguishes restored-from-disk state
// from a fresh in-memory job finish.
function mergeSummaryIntoPhaseResults(results, sum) {
  if (!sum) return;
  const promote = (kind, message, finishedAt) => {
    const cur = results[kind];
    if (!cur) return;
    if (cur.state !== "idle") return; // active state wins
    results[kind] = {
      ...cur,
      state: "succeeded",
      message: "persisted · " + message,
      finished_at: finishedAt || cur.finished_at || "",
    };
  };

  if (sum.parse && sum.parse.events_total > 0) {
    promote("parse",
      `${sum.parse.events_total.toLocaleString()} events · ${sum.parse.evidence_count} evidence`,
      sum.parse.last_parsed_at);
  }
  const t1a = (sum.tier1a && sum.tier1a.findings_count) || 0;
  const t1b = (sum.tier1b && sum.tier1b.findings_count) || 0;
  if (t1a + t1b > 0) {
    promote("analyze",
      `${t1a} Tier 1A · ${t1b} Tier 1B findings`,
      (sum.tier1b && sum.tier1b.last_updated) ||
      (sum.tier1a && sum.tier1a.last_updated) || "");
  }
  if (sum.synthesis && sum.synthesis.present) {
    promote("synthesize",
      `${sum.synthesis.clusters_count || 0} clusters · ${sum.synthesis.techniques_count || 0} techniques`,
      sum.synthesis.generated_at);
  }
  if (sum.report && (sum.report.formats || []).length > 0) {
    promote("report",
      `formats: ${(sum.report.formats || []).join(", ")}`,
      sum.report.generated_at);
  }
}

function statusPhaseBadgeClass(state) {
  if (state === "running")   return "badge warn";
  if (state === "succeeded") return "badge ok";
  if (state === "partial")   return "badge warn";
  if (state === "failed")    return "badge err";
  if (state === "canceled")  return "badge missing";
  return "badge missing";  // idle
}

function statusPhaseSymbol(state) {
  if (state === "running")   return "▶";
  if (state === "succeeded") return "✓";
  if (state === "partial")   return "⚠";
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

  // Case-state snapshot — fetched once on tab open; refreshed alongside
  // pipeline polling so newly-finished jobs surface within ~2 s.
  const snapshotHost = h("div", { class: "case-snapshot", id: "case_snapshot" });
  pane.appendChild(snapshotHost);
  await paintCaseSnapshot(snapshotHost, caseID);

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
    // JobStatus is in-memory and resets on server restart, so an "idle" phase
    // may actually have finished work persisted to disk. Fall back to the
    // case summary to surface that on-disk state.
    try {
      const sum = await api("GET", `/api/cases/${encodeURIComponent(caseID)}/summary`);
      mergeSummaryIntoPhaseResults(results, sum);
    } catch (_) { /* summary optional */ }
    paintOverview(overview, results);
    paintDetails(detailWrap, caseID, results);
    paintEventLog($("#status_event_log", pane));
    return anyRunning;
  }

  await tick();
  // Poll every 2 s. Same cadence as pipelinePolls so the two views agree.
  statusTabPollID = setInterval(async () => {
    const anyRun = await tick();
    // Refresh case snapshot when a job just transitioned to a terminal state,
    // so the summary picks up new findings / synthesis / reports.
    if (!anyRun) await paintCaseSnapshot(snapshotHost, caseID);
  }, 2000);
}

async function paintCaseSnapshot(host, caseID) {
  let sum;
  try {
    sum = await api("GET", `/api/cases/${encodeURIComponent(caseID)}/summary`);
  } catch (e) {
    host.innerHTML = `<div class="empty">summary unavailable: ${e.message}</div>`;
    return;
  }
  host.innerHTML = "";

  const card = h("div", { class: "card snapshot-card" });
  card.appendChild(h("div", { class: "card-header" }, [
    h("strong", {}, "Case snapshot"),
    h("span", { class: "muted", style: "margin-left: 8px; font-size: 12px;" },
      "(current artifact state, not job state)"),
  ]));

  const body = h("div", { class: "snapshot-body" });

  // Tier 0 — parse
  if (sum.parse) {
    const p = sum.parse;
    const artifacts = (p.artifacts || []).slice(0, 6)
      .map((a) => `${a.artifact_id}=${a.event_count.toLocaleString()}`)
      .join(" · ");
    const more = (p.artifacts || []).length > 6
      ? ` · +${p.artifacts.length - 6} more` : "";
    const parseTile = snapshotTile("Tier 0 · Parse",
      [
        kv("Evidence", p.evidence_count),
        kv("Events", p.events_total.toLocaleString()),
        kv("Last", fmtTS(p.last_parsed_at) || "—"),
      ],
      artifacts ? "Artifacts: " + artifacts + more : null
    );
    // Per-evidence breakdown — only when the case bundles >1 evidence, so
    // single-evidence cases keep the compact view. Each evidence is a
    // collapsible row that expands to its source host / type / top artifacts,
    // making it obvious which evidence the parsed events came from.
    const evs = p.evidence || [];
    if (evs.length > 1) {
      parseTile.appendChild(h("div", { class: "evidence-breakdown" }, [
        h("div", { class: "evidence-breakdown-title" }, "Per evidence"),
        ...evs.map(evidenceParseDetails),
      ]));
    }
    body.appendChild(parseTile);
  } else {
    body.appendChild(snapshotTile("Tier 0 · Parse",
      [h("span", { class: "muted" }, "no parsed events yet")], null));
  }

  // Collection completeness — distinguishes a DATA GAP from a detection MISS.
  if (sum.completeness) {
    const c = sum.completeness;
    const inputs = c.inputs || [];
    const present = inputs.filter((i) => i.present).length;
    const missing = inputs.filter((i) => !i.present);
    const rows = [
      kv("Inputs present", `${present}/${inputs.length}`),
      kv("Data gaps", c.missing_count +
        (c.missing_critical ? ` · ${c.missing_critical} critical` : "")),
    ];
    const footer = missing.length === 0
      ? "All catalogued detection inputs present."
      : "Not collected (absence ≠ detection failure): " +
        missing.map((i) => i.label).join(" · ");
    body.appendChild(snapshotTile("Collection completeness", rows, footer));
  }

  // Tier 1A
  body.appendChild(findingsTile("Tier 1A · Signature rules", sum.tier1a));
  // Tier 1B
  body.appendChild(findingsTile("Tier 1B · Skill anomalies", sum.tier1b));

  // Tier 2 synthesis
  if (sum.synthesis && sum.synthesis.present) {
    const s = sum.synthesis;
    const rows = [
      kv("Clusters", s.clusters_count || 0),
      kv("MITRE techniques", s.techniques_count || 0),
      kv("Open questions", s.open_questions_count || 0),
      kv("LLM calls", s.llm_calls_total || 0),
      kv("Generated", fmtTS(s.generated_at) || "—"),
    ];
    if (s.active_search_enabled) {
      rows.push(kv("Active SQL",
        `${s.active_sql_succeeded || 0}/${s.active_sql_attempted || 0} ok`));
      if (s.active_sql_self_corrected) {
        rows.push(kv("Self-corrected",
          `${s.active_sql_self_corrected} query(ies) recovered after revision`));
      }
    }
    body.appendChild(snapshotTile("Tier 2 · Synthesis", rows,
      s.model_id ? "model: " + s.model_id : null));
  } else {
    body.appendChild(snapshotTile("Tier 2 · Synthesis",
      [h("span", { class: "muted" }, "no synthesis.json yet")], null));
  }

  // Tier 3 report
  if (sum.report) {
    body.appendChild(snapshotTile("Tier 3 · Report",
      [
        kv("Formats", (sum.report.formats || []).join(", ")),
        kv("Generated", fmtTS(sum.report.generated_at) || "—"),
      ], null));
  } else {
    body.appendChild(snapshotTile("Tier 3 · Report",
      [h("span", { class: "muted" }, "no reports generated yet")], null));
  }

  card.appendChild(body);
  host.appendChild(card);
}

// evidenceParseDetails renders one EvidenceParseSummary as a collapsible
// <details> row: the summary line shows evidence_id + event count (visible
// while collapsed), and expanding reveals host / type / path / top artifacts.
function evidenceParseDetails(es) {
  const summary = h("summary", { class: "evidence-summary" }, [
    h("span", { class: "evidence-name" }, es.evidence_id || "(unattributed)"),
    h("span", { class: "evidence-count" }, (es.events_total || 0).toLocaleString() + " ev"),
  ]);
  const lines = [];
  const sub = [es.source_host, es.evidence_type].filter(Boolean).join(" · ");
  if (sub) lines.push(h("div", { class: "muted", style: "font-size: 11px;" }, sub));
  if (es.path) {
    lines.push(h("div", { class: "muted mono",
      style: "font-size: 10px; word-break: break-all;" }, es.path));
  }
  const topArts = (es.artifacts || []).slice(0, 8)
    .map((a) => `${a.artifact_id}=${a.event_count.toLocaleString()}`).join(" · ");
  const moreArts = (es.artifacts || []).length > 8
    ? ` · +${es.artifacts.length - 8} more` : "";
  if (topArts) {
    lines.push(h("div", { style: "font-size: 11px; margin-top: 4px;" }, topArts + moreArts));
  }
  if (es.last_event_at) {
    lines.push(h("div", { class: "muted", style: "font-size: 11px; margin-top: 4px;" },
      "last: " + (fmtTS(es.last_event_at) || "—")));
  }
  return h("details", { class: "evidence-item" },
    [summary, h("div", { class: "evidence-detail" }, lines)]);
}

function snapshotTile(title, rows, footer) {
  const tile = h("div", { class: "snapshot-tile" }, [
    h("div", { class: "snapshot-tile-title" }, title),
    ...rows,
  ]);
  if (footer) {
    tile.appendChild(h("div", { class: "muted", style: "font-size: 11px; margin-top: 6px;" }, footer));
  }
  return tile;
}

function findingsTile(title, fs) {
  if (!fs) {
    return snapshotTile(title,
      [h("span", { class: "muted" }, "no findings yet")], null);
  }
  const sevChips = ["critical","high","medium","low","info"]
    .filter((s) => (fs.by_severity || {})[s])
    .map((s) => h("span", { class: "badge sev-" + s, style: "margin-right: 4px;" },
      `${s}:${fs.by_severity[s]}`));
  const sources = Object.entries(fs.by_source || {})
    .map(([k,v]) => `${k}=${v}`).join(" · ");
  const tile = h("div", { class: "snapshot-tile" }, [
    h("div", { class: "snapshot-tile-title" }, title),
    h("div", { class: "snapshot-row" }, [
      h("span", { class: "k" }, "Total"),
      h("span", { class: "v" }, String(fs.findings_count)),
    ]),
    h("div", { class: "snapshot-row" }, [
      h("span", { class: "k" }, "Severity"),
      h("span", { class: "v" }, sevChips.length ? sevChips : "—"),
    ]),
    h("div", { class: "snapshot-row" }, [
      h("span", { class: "k" }, "Review"),
      h("span", { class: "v" },
        `pending:${fs.pending_count} · approved:${fs.approved_count} · auto:${fs.auto_approved_count} · rejected:${fs.rejected_count}`),
    ]),
  ]);
  if (sources) {
    tile.appendChild(h("div", { class: "muted", style: "font-size: 11px; margin-top: 6px;" },
      "Sources: " + sources));
  }
  return tile;
}

function kv(k, v) {
  return h("div", { class: "snapshot-row" }, [
    h("span", { class: "k" }, k),
    h("span", { class: "v" }, String(v)),
  ]);
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

  const records = data.records || [];
  const headers = data.headers || (data.header ? [data.header] : []);
  const headerByEv = {};
  headers.forEach((hd) => { headerByEv[hd.evidence_id || ""] = hd; });

  // Group records by source evidence (disk image) so a case bundling more
  // than one image keeps each image's extractions separate.
  const groups = new Map();
  records.forEach((r) => {
    const k = r.evidence_id || "";
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(r);
  });

  const cnt = (rows, st) => rows.filter((x) => (x.state || "pending") === st).length;
  const headerLine = (hd, rows) => {
    hd = hd || {};
    return `image: ${hd.image_path || "?"} · format: ${hd.image_format || "?"} · ` +
      `mount: ${hd.mount_method || "?"} · ` +
      `approved=${cnt(rows,"approved")} · pending=${cnt(rows,"pending")} · ` +
      `rejected=${cnt(rows,"rejected")}`;
  };

  if (groups.size <= 1) {
    // Single image — flat layout, visually unchanged from before.
    const first = [...groups][0];
    const k = first ? first[0] : "";
    const rows = first ? first[1] : records;
    exSection.appendChild(h("div", { class: "muted", style: "margin-bottom: 8px;" },
      headerLine(headerByEv[k], rows)));
    exSection.appendChild(extractTable(caseID, pane, rows));
  } else {
    // Multi-image — one collapsible group per evidence.
    exSection.appendChild(h("div", { class: "muted", style: "margin-bottom: 8px;" },
      `${groups.size} disk-image evidences — expand each to review its extractions.`));
    for (const [k, rows] of groups) {
      const hd = headerByEv[k] || {};
      const summary = h("summary", { class: "evidence-summary" }, [
        h("span", { class: "evidence-name" }, k || "(image)"),
        h("span", { class: "muted", style: "font-size: 11px;" },
          `${hd.image_format || "?"} · ${hd.mount_method || "?"}`),
        h("span", { class: "evidence-count" },
          `${rows.length} files · ✓${cnt(rows,"approved")} · ⏳${cnt(rows,"pending")}`),
      ]);
      const detail = h("div", { class: "evidence-detail" }, [
        h("div", { class: "muted mono",
          style: "font-size: 10px; margin-bottom: 6px; word-break: break-all;" },
          hd.image_path || ""),
        extractTable(caseID, pane, rows),
      ]);
      exSection.appendChild(h("details", { class: "evidence-item", open: "open" },
        [summary, detail]));
    }
  }

  // Always position the Extracts section above Parse Results — `insertBefore`
  // with the current first child keeps the layout stable across re-renders
  // (approve/reject would otherwise append to the bottom).
  if (pane.firstChild) {
    pane.insertBefore(exSection, pane.firstChild);
  } else {
    pane.appendChild(exSection);
  }
}

// extractTable builds the extract-record table for one evidence's rows.
// Shared by the flat (single-image) and grouped (multi-image) renders.
function extractTable(caseID, pane, records) {
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
  (records || []).forEach((r) => body.appendChild(extractRow(caseID, pane, r)));
  tbl.appendChild(body);
  return tbl;
}

// extractRow renders one extract record. The approve/reject calls use the
// server-supplied review_key (evidence-namespaced) so same-named targets on
// different images don't share review state; r.target is kept for display.
function extractRow(caseID, pane, r) {
  const key = r.review_key || r.target;
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
            `/api/cases/${encodeURIComponent(caseID)}/extracts/${encodeURIComponent(key)}/approve`);
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
                  `/api/cases/${encodeURIComponent(caseID)}/extracts/${encodeURIComponent(key)}/reject`,
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
  return h("tr", {}, [
    h("td", {}, h("code", {}, r.target)),
    h("td", {}, h("span", { class: "badge " + statusClass, title: r.error || "" }, r.status)),
    h("td", {}, r.partition != null ? String(r.partition) : "—"),
    h("td", { class: "mono" }, r.inum || "—"),
    h("td", {}, r.bytes != null ? Number(r.bytes).toLocaleString() : "—"),
    h("td", { class: "mono", style: "font-size: 10px;" },
      r.sha256 ? r.sha256.slice(0, 16) + "…" : "—"),
    h("td", {}, stateBadge),
    h("td", {}, action),
  ]);
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

  // Evidence metadata for the filter dropdown + per-evidence grouping labels.
  // Stashed on the card so loadEventsPage (called from Prev/Next without
  // `detail` in scope) can still resolve evidence_id → host/type.
  const evidences = (detail && detail.evidence) || [];
  browserCard._evMeta = evidences;

  // Filter form
  const artifactIDs = [...new Set(prs.map((p) => p.artifact_id).filter(Boolean))].sort();
  // Evidence selector only appears for multi-evidence cases — single-evidence
  // cases gain nothing from it and the events already all share one source.
  const evField = evidences.length > 1
    ? h("div", { class: "f-field" }, [
        h("label", {}, "Evidence"),
        h("select", { id: "ev_evidence" },
          [h("option", { value: "" }, "(all)"),
           ...evidences.map((e) => h("option", { value: e.evidence_id },
             e.evidence_id + (e.source_host ? ` (${e.source_host})` : "")))]),
      ])
    : null;
  const filterRow = h("div", { class: "filter-row" }, [
    evField,
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
  const evSel    = browserCard.querySelector("#ev_evidence");
  const evidence = evSel ? evSel.value : "";
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

  if (evidence) q.set("evidence_id", evidence);
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

  // Group the returned page by evidence_id so it's clear which source each
  // event came from. Single-evidence cases render the flat table exactly as
  // before. Multi-evidence cases always render labelled sections — even when
  // a ts-ordered page happens to contain just one evidence — so the source is
  // never ambiguous.
  const groups = new Map();
  data.events.forEach((e) => {
    const k = e.evidence_id || "";
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(e);
  });

  const multiEvidence = (browserCard._evMeta || []).length > 1;
  if (!multiEvidence && groups.size <= 1) {
    resultsBox.appendChild(eventsTable(data.events));
    return;
  }

  const meta = {};
  (browserCard._evMeta || []).forEach((e) => { meta[e.evidence_id] = e; });
  if (groups.size > 1) {
    resultsBox.appendChild(h("div", { class: "muted", style: "font-size: 11px; margin-bottom: 8px;" },
      "Grouped by evidence (within the current page). Use the Evidence filter to scope a single source."));
  }
  for (const [k, rows] of groups) {
    const m = meta[k] || {};
    const sub = [m.source_host, m.evidence_type].filter(Boolean).join(" · ");
    const summary = h("summary", { class: "evidence-summary" }, [
      h("span", { class: "evidence-name" }, k || "(unattributed)"),
      sub ? h("span", { class: "muted", style: "font-size: 11px;" }, sub) : null,
      h("span", { class: "evidence-count" }, rows.length + " ev"),
    ]);
    resultsBox.appendChild(h("details", { class: "evidence-item", open: "open" },
      [summary, h("div", { class: "evidence-detail" }, eventsTable(rows))]));
  }
}

// eventsTable builds the unified_events result table for a set of rows.
// Shared by the flat (single-evidence) and grouped (multi-evidence) renders.
function eventsTable(rows) {
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
  rows.forEach((e) => {
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
  return tbl;
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
// History is browser-local only (key: tlvb:chat:<caseID|global>).
// ============================================================================

const CHAT_STORAGE_PREFIX = "tlvb:chat:";
const CHAT_PRIVACY_ACK    = "tlvb:chat:privacy-ack";
const CHAT_PREFS          = "tlvb:chat:prefs";

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
  const fab = h("button", { class: "chat-fab", id: "chat-fab", title: "TLVB Assistant" }, "💬");
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
    ? "context: TLVB documentation"
    : `context: case ${scope}`;

  drawer.innerHTML = "";
  drawer.appendChild(h("div", { class: "chat-header" }, [
    h("span", { class: "title" }, "TLVB Assistant"),
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
      placeholder: "Ask about TLVB, or about this case's findings...  (Enter to send, Shift+Enter newline)",
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
      ? "Try: 「TLVB の使い方を教えて」/ 「Tier 1A signature SQL Agent は何をしている？」"
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
      "TLVB Assistant について:\n\n" +
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
