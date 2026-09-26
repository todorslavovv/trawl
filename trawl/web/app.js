/* trawl investigation UI.
 * Security note: every piece of data reaches the DOM through textContent or
 * setAttribute on a fixed attribute name. There is no innerHTML, no eval, and the
 * only URLs built from data are same-origin hash routes (encodeURIComponent) and
 * crt.sh links built from integer ids.
 *
 * Language: Bulgarian by default, English as the alternative. Every user-visible
 * string comes from /i18n.json. Data (domain names, hashes, rule ids, indicator
 * values) is never translated. Evidence sentences produced by the analysis are
 * stored in English; in Bulgarian they are rendered through the pattern table in
 * i18n.json, so the stored evidence - and its fingerprints - never change.
 */
"use strict";
(() => {
  const SVGNS = "http://www.w3.org/2000/svg";
  const view = document.getElementById("view");
  const tip = document.getElementById("tip");
  const LANGS = ["bg", "en"];
  let META = null;
  let I18N = null;
  let PATTERNS = [];
  let LANG = "bg";
  let renderToken = 0;

  // ---------------------------------------------------------------- language
  function savedLang() {
    try { const v = localStorage.getItem("trawl.lang"); return LANGS.includes(v) ? v : "bg"; } catch { return "bg"; }
  }
  function t(key, params) {
    let s = I18N?.[LANG]?.[key] ?? I18N?.en?.[key] ?? key;
    if (params) s = s.replace(/\{(\w+)\}/g, (m, k) => (params[k] === undefined || params[k] === null ? m : String(params[k])));
    return s;
  }
  // Translate an English evidence sentence produced by the analysis (Bulgarian only).
  function tx(text) {
    if (text === null || text === undefined || text === "") return text ?? "";
    if (LANG === "en") return String(text);
    const kinds = (s) => s.replace(/\{kinds:([^}]*)\}/g, (_, list) => list.split(", ").map((k) => label("kind", k)).join(", "));
    const match = (s) => {
      for (const [re, rep] of PATTERNS) if (re.test(s)) return kinds(brandNames(s.replace(re, rep)));
      return null;
    };
    // Whole sentence first (some contain "; "), then the "; "-joined parts that
    // multi-brand details are built from.
    const whole = match(String(text));
    if (whole !== null) return whole;
    return String(text).split("; ").map((part) => match(part) ?? brandNames(I18N.phrases_bg?.[part] ?? part)).join("; ");
  }
  function brandNames(s) {
    let out = s;
    // longer phrases first (namesake descriptions contain brand names)
    for (const [en, bg] of Object.entries(I18N.phrases_bg || {})) out = out.split(en).join(bg);
    if (!META) return out;
    for (const [id, b] of Object.entries(META.brands)) {
      const bg = I18N?.bg?.[`brand.${id}`];
      if (bg) out = out.split(b.label).join(bg);
    }
    return out;
  }
  const label = (group, id) => (id === null || id === undefined ? "–" : (I18N?.[LANG]?.[`${group}.${id}`] ?? I18N?.en?.[`${group}.${id}`] ?? String(id)));
  const brandLabel = (id) => label("brand", id) === id ? (META?.brands?.[id]?.label || id) : label("brand", id);

  // ---------------------------------------------------------------- dom helpers
  function setAttrs(el, attrs) {
    if (!attrs) return;
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.setAttribute("class", v);
      else if (k === "text") el.textContent = String(v);
      else if (k === "style" && typeof v === "object") for (const [p, pv] of Object.entries(v)) el.style.setProperty(p, pv);
      else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
  }
  function add(el, kids) {
    for (const kid of kids.flat(Infinity)) {
      if (kid === null || kid === undefined || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }
  const h = (tag, attrs, ...kids) => { const el = document.createElement(tag); setAttrs(el, attrs); return add(el, kids); };
  const s = (tag, attrs, ...kids) => { const el = document.createElementNS(SVGNS, tag); setAttrs(el, attrs); return add(el, kids); };

  // ---------------------------------------------------------------- formatting
  let fmt = new Intl.NumberFormat("bg-BG");
  const n = (x) => (x === null || x === undefined ? "–" : fmt.format(x));
  const dec2 = (x) => (x === null || x === undefined ? "–" : new Intl.NumberFormat(LANG === "bg" ? "bg-BG" : "en-GB", { minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(x));
  const pct = (x) => (x === null || x === undefined ? "–" : `${new Intl.NumberFormat(LANG === "bg" ? "bg-BG" : "en-GB", { maximumFractionDigits: x < 0.1 ? 1 : 0 }).format(x * 100)}%`);
  const day = (iso) => (iso ? String(iso).slice(0, 10) : "–");
  const dt = (iso) => (iso ? String(iso).replace("T", " ").slice(0, 16) : "–");
  const short = (sha, k = 12) => (sha ? String(sha).slice(0, k) : "–");
  function ago(iso) {
    if (!iso) return "–";
    const tt = Date.parse(String(iso).length <= 19 ? iso + "Z" : iso);
    if (Number.isNaN(tt)) return "–";
    const d = (Date.now() - tt) / 1000;
    if (d < 90) return t("time.just_now");
    if (d < 5400) return t("time.min_ago", { n: Math.round(d / 60) });
    if (d < 172800) return t("time.h_ago", { n: Math.round(d / 3600) });
    return t("time.d_ago", { n: Math.round(d / 86400) });
  }
  const secs = (x) => (x === null || x === undefined ? "–" : x < 90 ? t("unit.s", { n: x.toFixed(0) }) : x < 5400 ? t("unit.min", { n: (x / 60).toFixed(1) }) : t("unit.h", { n: (x / 3600).toFixed(1) }));
  const bytes = (b) => (b === null || b === undefined ? "–" : b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(0)} kB` : `${(b / 1048576).toFixed(1)} MB`);
  const issuerShort = (name) => (name || "").replace(/^.*CN=/, "");

  const VCOL = { likely: "var(--likely)", possible: "var(--possible)", lead: "var(--lead)", weak: "var(--weak)", none: "var(--none)", legitimate: "var(--legit)" };

  const chip = (cls, text, title) => h("span", { class: `chip ${cls}`, title }, text);
  const verdictChip = (v) => chip(`v-${v}`, label("verdict", v), label("verdict_text", v));
  const dnsChip = (o) => { const k = o || "unchecked"; return h("span", { class: `nowrap d-${k}`, title: o || "" }, h("span", { class: "dot" }), label("dns", k)); };
  const tierChip = (x) => chip(`t-${x}`, label("tier", x), label("tier_text", x));
  const statusChip = (st) => h("span", { class: `nowrap s-${st}` }, h("span", { class: "dot" }), label("status", st));
  const tag = (x, title) => h("span", { class: "tag", title }, x);
  const domLink = (name) => h("a", { href: `#/domain?name=${encodeURIComponent(name)}` }, name);
  const campLink = (id) => h("a", { class: "mono", href: `#/campaign?id=${encodeURIComponent(id)}` }, id);
  const crtLink = (id) => h("a", { href: `https://crt.sh/?id=${Number(id)}`, target: "_blank", rel: "noopener noreferrer", class: "mono", title: t("link.crtsh_title") }, `crt.sh/${Number(id)} ↗`);
  const kindLabel = (k) => h("span", { title: k }, label("kind", k));
  const addrList = (addrs) => (addrs && addrs.length ? h("div", { class: "addr-list" }, addrs.map((a) => h("div", {}, a))) : "–");
  const brandTag = (b) => tag(brandLabel(b), b);

  // public layer: local date/time, plain-language status and availability
  function toDate(iso) {
    if (!iso) return null;
    const str = String(iso);
    const tt = Date.parse(/[zZ]$|[+-]\d\d:\d\d$/.test(str) ? str : `${str}Z`);
    return Number.isNaN(tt) ? null : new Date(tt);
  }
  const pad2 = (x) => String(x).padStart(2, "0");
  function pubDate(iso) {
    const d = toDate(iso);
    if (!d) return "–";
    return LANG === "bg" ? `${pad2(d.getDate())}.${pad2(d.getMonth() + 1)}.${d.getFullYear()}`
      : d.toLocaleDateString("en-GB");
  }
  const pubDateTime = (iso) => { const d = toDate(iso); return d ? `${pubDate(iso)} ${pad2(d.getHours())}:${pad2(d.getMinutes())}` : "–"; };
  const when = (iso, withTime) => h("time", { class: "nowrap", datetime: iso, title: iso ? `${dt(iso)} UTC` : null }, withTime ? pubDateTime(iso) : pubDate(iso));
  const pubStatus = (v) => chip(`v-${v}`, label("pub.status", v), label("pub.status_text", v));
  const availChip = (st) => h("span", { class: `nowrap av av-${st}`, title: label("avail.public_text", st) }, h("span", { class: "dot" }), label("avail.public", st));
  const PUBLIC_OF = { reachable: "reachable", unreachable: "unreachable" };
  const stateChip = (st) => h("span", { class: `nowrap av av-${PUBLIC_OF[st] || "unknown"}`, title: st }, h("span", { class: "dot" }), label("avail.state", st));
  const reasonText = (o) => t(`avail.reason.${o.reason}`, { status: o.http_status ?? "" });
  const protText = (o) => [o.protection, o.challenge ? t("dd.av.challenge") : null].filter(Boolean).join(" · ") || "–";
  function scoreBar(score, verdict) {
    return h("span", { class: "scorebar" }, h("span", { class: "mono" }, score),
      h("i", {}, h("b", { style: { width: `${Math.max(2, score)}%`, "--c": VCOL[verdict] || "var(--accent)" } })));
  }
  function card(title, hint, ...body) {
    return h("section", { class: "card" }, h("header", {}, h("h2", {}, title), hint ? h("span", { class: "hint" }, hint) : null), ...body);
  }
  const empty = (msg) => h("div", { class: "empty" }, msg);
  function table(cols, rows, opts = {}) {
    // Column names for the stacked phone layout; the domain column is the record title.
    const labelText = cols.map((c) => (c.cls === "dom" ? null
      : typeof c.label === "string" ? c.label : (c.label?.textContent || "").replace(/[↑↓]/g, "").trim() || null));
    const thead = h("thead", {}, h("tr", {}, cols.map((c) => h("th", { class: c.num ? "num" : null, title: c.title }, c.label))));
    const tbody = h("tbody", {}, rows.map((r) => {
      const tr = h("tr", { class: [opts.rowClass?.(r), opts.onRow ? "link" : null].filter(Boolean).join(" ") || null },
        cols.map((c, i) => h("td", { class: [c.num ? "num" : null, c.cls].filter(Boolean).join(" ") || null, "data-label": labelText[i] }, c.cell(r))));
      if (opts.onRow) tr.addEventListener("click", (e) => { if (!e.target.closest("a")) opts.onRow(r); });
      return tr;
    }));
    return h("div", { class: "tbl-wrap" }, h("table", {}, thead, tbody), rows.length ? null : empty(opts.empty || t("empty.default")));
  }
  function kv(pairs) {
    return h("dl", { class: "kv" }, pairs.filter(Boolean).map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
  }
  function pager(total, offset, size, onPrev, onNext, what) {
    return h("div", { class: "pager" },
      h("span", {}, t("pager.showing", { total: n(total), what, from: total ? offset + 1 : 0, to: Math.min(offset + size, total) })),
      h("span", {}, h("button", { class: "btn", disabled: offset === 0 ? true : null, onclick: onPrev }, t("pager.prev")), " ",
        h("button", { class: "btn", disabled: offset + size >= total ? true : null, onclick: onNext }, t("pager.next"))));
  }

  // tooltips
  function tipOn(el, content) {
    el.addEventListener("mouseenter", () => { tip.replaceChildren(content()); tip.hidden = false; });
    el.addEventListener("mousemove", (e) => {
      const w = tip.offsetWidth, hgt = tip.offsetHeight;
      tip.style.left = `${Math.max(4, Math.min(e.clientX + 14, innerWidth - w - 8))}px`;
      tip.style.top = `${Math.max(4, Math.min(e.clientY + 14, innerHeight - hgt - 8))}px`;
    });
    el.addEventListener("mouseleave", () => { tip.hidden = true; });
  }

  // ---------------------------------------------------------------- api + routing
  class ApiError extends Error {}
  async function api(path, params = {}) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") qs.set(k, v);
    const url = `/api/${path}${[...qs].length ? `?${qs}` : ""}`;
    const r = await fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" });
    let j;
    try { j = await r.json(); } catch { j = { error: `HTTP ${r.status}` }; }
    if (!r.ok) throw new ApiError(j.error || `HTTP ${r.status}`);
    return j;
  }
  function parseHash() {
    const raw = location.hash.replace(/^#\/?/, "");
    const i = raw.indexOf("?");
    return { path: i < 0 ? raw : raw.slice(0, i), params: new URLSearchParams(i < 0 ? "" : raw.slice(i + 1)) };
  }
  function go(path, params) {
    const qs = params ? new URLSearchParams(Object.entries(params).filter(([, v]) => v !== "" && v !== null && v !== undefined)).toString() : "";
    location.hash = `#/${path}${qs ? `?${qs}` : ""}`;
  }

  const ICONS = {
    registry: "M4 3h12v14H4zM7 7h6M7 10h6M7 13h4",
    overview: "M3 3h6v8H3zM11 3h6v5h-6zM11 10h6v7h-6zM3 13h6v4H3z",
    domains: "M10 2a8 8 0 100 16 8 8 0 000-16zM2 10h16M10 2c2.5 2.2 3.5 5 3.5 8s-1 5.8-3.5 8c-2.5-2.2-3.5-5-3.5-8s1-5.8 3.5-8z",
    certificates: "M4 3h12v10H4zM7 7h6M7 10h4M8 13l-1 5 3-2 3 2-1-5",
    campaigns: "M5 5a2 2 0 110 .1M15 4a2 2 0 110 .1M10 14a2 2 0 110 .1M5 5l5 9M15 4l-5 10M5 5l10-1",
    timeline: "M3 10h14M6 6v8M10 4v12M14 7v6",
    sources: "M4 4h12v4H4zM4 12h12v4H4zM7 6h.1M7 14h.1",
    collection: "M3 16l4-6 3 3 4-7 3 4M3 3v14h14",
    methodology: "M5 3h8l3 3v11H5zM8 9h6M8 12h6M8 15h4",
  };
  // Public registry first; the analyst views are one click away under "Analysis".
  const NAV = [["", "registry"], "analysis", ["analysis", "overview"], ["domains", "domains"], ["certificates", "certificates"],
    ["campaigns", "campaigns"], ["timeline", "timeline"], null, ["sources", "sources"], ["collection", "collection"], ["methodology", "methodology"]];
  const SECTION_OF = { domain: "domains", certificate: "certificates", campaign: "campaigns", run: "collection" };

  function buildNav() {
    const nav = document.getElementById("nav");
    nav.replaceChildren(...NAV.map((item) => {
      if (!item) return h("div", { class: "sep" });
      if (typeof item === "string") return h("div", { class: "nav-group" }, t(`nav.group.${item}`));
      const [path, icon] = item;
      return h("a", { href: `#/${path}`, "data-p": path },
        s("svg", { viewBox: "0 0 20 20", "aria-hidden": "true" }, s("path", { d: ICONS[icon], fill: "none", stroke: "currentColor", "stroke-width": "1.5", "stroke-linecap": "round", "stroke-linejoin": "round" })),
        t(`nav.${icon}`));
    }));
  }
  function setNav(path, crumbs) {
    const sec = SECTION_OF[path] ?? path;
    for (const a of document.querySelectorAll("#nav a")) a.classList.toggle("on", a.dataset.p === sec);
    const c = document.getElementById("crumbs");
    c.replaceChildren(...(crumbs || []).flatMap((x, i) => [i ? " / " : null, i === crumbs.length - 1 ? h("b", {}, x) : x]).filter((x) => x !== null));
  }
  function errorBox(e) {
    const msg = String(e?.message || e);
    return h("div", { class: "errbox" }, h("b", {}, t("error.load")), " ", e instanceof ApiError ? tx(msg) : h("span", { class: "mono" }, msg));
  }

  let lastPath = null;
  async function render() {
    const { path, params } = parseHash();
    const page = PAGES[path] || notFound;
    const token = ++renderToken;
    const title = page.titleKey ? t(page.titleKey) : "trawl";
    document.body.classList.toggle("public", !!page.public);
    setNav(path, [title]);
    if (path !== lastPath) scrollTo(0, 0);
    lastPath = path;
    document.title = `${title} · trawl`;
    view.replaceChildren(h("div", { class: "loading" }, t("loading")));
    try {
      const node = await page(params);
      if (token !== renderToken) return;
      view.replaceChildren(node);
      view.style.animation = "none"; void view.offsetWidth; view.style.animation = "";
      if (page.crumbs) setNav(path, page.crumbs(params));
      if (page.public && params.get("q")) document.querySelector(".result")?.scrollIntoView({ block: "nearest" });
    } catch (e) {
      if (token !== renderToken) return;
      view.replaceChildren(errorBox(e));
    }
  }

  // ---------------------------------------------------------------- charts
  function stackedBars({ data, keys, colors, height = 150, xlabel, tipFor, onClick, aria }) {
    const W = 760, H = height, padL = 30, padB = 18, padT = 6;
    const max = Math.max(1, ...data.map((d) => keys.reduce((a, k) => a + (d[k] || 0), 0)));
    const nice = niceMax(max);
    const bw = Math.min((W - padL) / Math.max(1, data.length), 34);   // few bars stay bars
    const y = (v) => H - padB - (v / nice) * (H - padB - padT);
    const svg = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": aria || "" });
    for (const tv of [0, nice / 2, nice]) {
      svg.append(s("line", { class: "grid-l", x1: padL, x2: W, y1: y(tv), y2: y(tv) }));
      svg.append(s("text", { x: padL - 6, y: y(tv) + 3, "text-anchor": "end" }, n(Math.round(tv))));
    }
    data.forEach((d, i) => {
      const g = s("g", { class: "col" });
      let acc = 0;
      for (const k of keys) {
        const v = d[k] || 0;
        if (!v) continue;
        g.append(s("rect", { class: "bar grow", x: padL + i * bw + 1, width: Math.max(1, bw - 2), y: y(acc + v), height: Math.max(0.5, y(acc) - y(acc + v)), fill: colors[k], rx: 1.5, style: { "animation-delay": `${i * 6}ms` } }));
        acc += v;
      }
      g.append(s("rect", { x: padL + i * bw, width: bw, y: padT, height: H - padB - padT, fill: "transparent" }));
      if (tipFor) tipOn(g, () => tipFor(d));
      if (onClick) { g.style.cursor = "pointer"; g.addEventListener("click", () => onClick(d)); }
      const lab = xlabel?.(d, i);
      if (lab) svg.append(s("text", { x: padL + i * bw + bw / 2, y: H - 4, "text-anchor": "middle" }, lab));
      svg.append(g);
    });
    return svg;
  }
  function niceMax(v) {
    const p = 10 ** Math.floor(Math.log10(v));
    for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
    return 10 * p;
  }
  function legend(items) {
    return h("div", { class: "legend" }, items.map(([text, color]) => h("span", {}, h("i", { style: { background: color } }), text)));
  }
  function hbars(rows, keys, colors, labelFor, hrefFor) {
    const max = Math.max(1, ...rows.map((r) => keys.reduce((a, k) => a + (r[k] || 0), 0)));
    return h("div", {}, rows.map((r, i) => {
      const tot = keys.reduce((a, k) => a + (r[k] || 0), 0);
      const lab = hrefFor ? h("a", { href: hrefFor(r) }, labelFor(r)) : labelFor(r);
      const row = h("div", { class: "hbar" }, h("span", { class: "nowrap", style: { overflow: "hidden", "text-overflow": "ellipsis" } }, lab),
        h("span", { class: "track" }, keys.map((k) => h("span", { style: { width: `${((r[k] || 0) / max) * 100}%`, background: colors[k], "animation-delay": `${i * 30}ms` } }))),
        h("span", { class: "num mono" }, n(tot)));
      tipOn(row, () => h("div", {}, h("b", {}, labelFor(r)), keys.map((k) => h("div", {}, `${label("verdict", k)}: ${n(r[k] || 0)}`))));
      return row;
    }));
  }
  const OUTCOME_COL = { ok: "var(--live)", ok_empty: "#2f8f6c", abandoned: "var(--possible)", timeout: "#e08a3c", http_error: "var(--likely)", network_error: "var(--likely)", parse_error: "var(--likely)", too_large: "var(--likely)", skipped: "var(--faint)" };
  function runStrip(runs) {
    const data = runs.slice().reverse().map((r) => ({
      ...r, ok: r.queries_ok, empty: r.queries_empty, abandoned: r.queries_abandoned,
      timeout: r.queries_timeout, failed: r.queries_failed, skipped: r.queries_skipped,
    }));
    const cols = { ok: OUTCOME_COL.ok, empty: OUTCOME_COL.ok_empty, abandoned: OUTCOME_COL.abandoned, timeout: OUTCOME_COL.timeout, failed: OUTCOME_COL.http_error, skipped: OUTCOME_COL.skipped };
    return h("div", {},
      stackedBars({ data, keys: Object.keys(cols), colors: cols, height: 120, aria: t("health.aria"),
        tipFor: (d) => h("div", {}, h("b", {}, t("health.tip_run", { id: d.id, status: label("status", d.status) })), h("div", {}, `${dt(d.started_at)} UTC`),
          h("div", {}, t("health.tip_answered", { a: d.ok + d.empty, n: d.queries_requested })), d.abandoned ? h("div", {}, t("health.tip_abandoned", { n: d.abandoned })) : null,
          d.timeout ? h("div", {}, t("health.tip_timeout", { n: d.timeout })) : null, d.failed ? h("div", {}, t("health.tip_failed", { n: d.failed })) : null),
        onClick: (d) => go("run", { id: d.id }) }),
      legend(Object.keys(cols).map((k) => [t(`health.legend.${k}`), cols[k]])));
  }

  // ---------------------------------------------------------------- pages
  const PAGES = {};

  const REG_SIZE = 50;
  PAGES[""] = async function registry(params) {
    const q = (params.get("q") || "").trim();
    const page = Math.max(1, parseInt(params.get("page") || "1", 10) || 1);
    const [reg, look] = await Promise.all([
      api("registry", { limit: REG_SIZE, offset: (page - 1) * REG_SIZE }),
      q ? api("lookup", { q }).catch((e) => ({ error: e })) : null,
    ]);
    const input = h("input", { type: "search", name: "q", value: q, maxlength: "1000", spellcheck: "false", autocomplete: "off", autocapitalize: "none",
      placeholder: t("reg.search_ph"), "aria-label": t("reg.search_aria") });
    const form = h("form", { class: "reg-search", role: "search", onsubmit: (e) => { e.preventDefault(); const v = input.value.trim(); go("", v ? { q: v } : {}); } },
      s("svg", { viewBox: "0 0 20 20", "aria-hidden": "true" }, s("circle", { cx: 8.5, cy: 8.5, r: 5.5, fill: "none", stroke: "currentColor", "stroke-width": "1.6" }), s("path", { d: "M13 13l4.5 4.5", stroke: "currentColor", "stroke-width": "1.6", "stroke-linecap": "round" })),
      input, h("button", { class: "btn primary", type: "submit" }, t("reg.search_btn")));
    const u = reg.updated;
    const updated = h("p", { class: "reg-updated" }, t("reg.updated", { at: pubDateTime(u.analysis_at) }), " · ",
      u.availability_at ? t("reg.checked", { at: pubDateTime(u.availability_at) }) : t("reg.checked_never"), h("span", { class: "faint" }, ` (${t("reg.local_time")})`));
    const pages = Math.max(1, Math.ceil(reg.total / REG_SIZE));
    const rows = table([
      { label: t("reg.col.domain"), cls: "dom", cell: (r) => h("a", { href: `#/?q=${encodeURIComponent(r.name)}` }, r.name) },
      // wrap at spaces, never inside "е-винетка" (non-breaking hyphen, display only)
      { label: t("reg.col.brand"), cell: (r) => (r.brands.length ? r.brands.map((b) => brandLabel(b).replace(/-/g, "\u2011")).join(", ") : "–") },
      { label: t("reg.col.status"), cell: (r) => pubStatus(r.verdict) },
      { label: t("reg.col.date"), cell: (r) => when(r.first_seen_at) },
      // last check and the state it found belong together: one column, date then state
      { label: t("reg.col.checked"), cell: (r) => (r.availability.last_checked
        ? h("span", { class: "reg-check" }, when(r.availability.last_checked, true), availChip(r.availability.state))
        : availChip("unchecked")) },
    ], reg.rows, { empty: t("reg.empty") });
    const tableCard = h("section", { class: "card flush reg-table" },
      h("header", {}, h("h2", {}, t("reg.table_title")), h("span", { class: "hint" }, t("reg.table_hint", { n: n(reg.total) }))),
      rows, pager(reg.total, (page - 1) * REG_SIZE, REG_SIZE, () => go("", { page: Math.max(1, page - 1) }), () => go("", { page: Math.min(pages, page + 1) }), t("pager.domains")));
    return h("div", { class: "registry" },
      h("div", { class: "reg-hero" }, h("h1", {}, t("reg.title")), h("p", { class: "lead" }, t("reg.intro")), form, updated),
      look ? lookupCard(look) : null, tableCard,
      h("p", { class: "reg-note" }, t("reg.note_reachable")));
  };
  PAGES[""].titleKey = "nav.registry";
  PAGES[""].public = true;
  function lookupCard(look) {
    if (look.error) {
      return h("section", { class: "card result miss", role: "status" }, h("h2", {}, t("reg.invalid_title")), h("p", {}, t("reg.invalid_text")));
    }
    const tech = (name) => h("a", { class: "btn", href: `#/domain?name=${encodeURIComponent(name)}` }, t("reg.technical"));
    if (look.in_registry) {
      const e = look.entry, a = e.availability;
      return h("section", { class: "card result hit", role: "status" },
        h("h2", {}, t("reg.found_title")), h("div", { class: "result-name" }, e.name),
        look.matched !== look.host ? h("p", { class: "muted" }, t("reg.matched_www", { host: look.host, name: look.matched })) : null,
        kv([
          [t("reg.f.status"), pubStatus(e.verdict)],
          e.brands.length ? [t("reg.f.brand"), e.brands.map(brandLabel).join(", ")] : null,
          [t("reg.f.first_seen"), when(e.first_seen_at)],
          [t("reg.f.last_checked"), a.last_checked ? when(a.last_checked, true) : t("reg.not_checked")],
          [t("reg.f.last_reachable"), a.last_reachable ? when(a.last_reachable, true) : t("reg.never_confirmed")],
          [t("reg.f.state"), availChip(a.state)],
        ]),
        h("p", { class: "reg-note" }, t("reg.note_reachable")), tech(e.name));
    }
    return h("section", { class: "card result miss", role: "status" },
      h("h2", {}, t("reg.missing_title")), h("div", { class: "result-name" }, look.host),
      h("p", { class: "warnline" }, t("reg.not_safe")),
      look.known ? h("p", {}, t("reg.known_not_listed"), " ", tech(look.matched)) : null,
      h("p", { class: "muted" }, t("reg.db_only")));
  }

  PAGES.analysis = async function overview() {
    const o = await api("overview");
    const v = o.verdicts;
    const dns = o.dns || {};
    const checked = Object.entries(dns).filter(([k]) => k !== "unchecked").reduce((a, [, x]) => a + x, 0);
    const last = o.collection.last_crtsh;
    const cov = last?.note?.coverage || {};
    const covVals = Object.values(cov);
    const tiers = o.campaign_tiers || {};
    const kpis = h("div", { class: "kpis" },
      kpi(t("ov.kpi.flagged"), n(o.flagged), t("ov.kpi.flagged_sub", { likely: n(v.likely || 0), possible: n(v.possible || 0), lead: n(v.lead || 0) }), "var(--likely)", "#/domains"),
      kpi(t("ov.kpi.issued30"), n(o.issued_30d), t("ov.kpi.issued30_sub"), "var(--possible)", "#/domains?since_days=30&since_field=first_issued&sort=first_issued"),
      kpi(t("ov.kpi.new7"), n(o.new_7d), t("ov.kpi.new7_sub"), "var(--accent)", "#/domains?since_days=7&sort=first_seen"),
      kpi(t("ov.kpi.resolving"), n(dns.resolved || 0), t("ov.kpi.resolving_sub", { checked: n(checked), unchecked: n(dns.unchecked || 0) }), "var(--live)", "#/domains?dns=resolved"),
      kpi(t("ov.kpi.campaigns"), n(Object.values(tiers).reduce((a, x) => a + x, 0)), t("ov.kpi.campaigns_sub", { strong: n(tiers.strong || 0), corroborated: n(tiers.corroborated || 0), chained: n(tiers.chained || 0) }), "var(--corr)", "#/campaigns"),
      kpi(t("ov.kpi.lastrun"), last ? label("status", last.status) : t("ov.kpi.lastrun_none"),
        last ? t("ov.kpi.lastrun_sub", { full: covVals.filter((x) => x === "full").length, total: covVals.length, ago: ago(last.finished_at || last.started_at) }) : t("ov.kpi.lastrun_none_sub"),
        last?.status === "complete" ? "var(--live)" : "var(--possible)", last ? `#/run?id=${last.id}` : "#/collection"));

    const weekly = card(t("ov.weekly.title"), t("ov.weekly.hint"),
      stackedBars({ data: o.weekly_issuance, keys: ["likely", "possible", "lead"], colors: { likely: VCOL.likely, possible: VCOL.possible, lead: VCOL.lead }, aria: t("ov.weekly.title"),
        xlabel: (d, i) => (i % 8 === 0 ? d.week.slice(2, 10) : ""),
        tipFor: (d) => h("div", {}, h("b", {}, t("ov.weekly.tip_week", { week: d.week })), h("div", {}, `${label("verdict", "likely")} ${d.likely} · ${label("verdict", "possible")} ${d.possible} · ${label("verdict", "lead")} ${d.lead}`), h("div", { class: "muted" }, t("ov.weekly.tip_click"))),
        onClick: (d) => go("domains", { since_days: Math.ceil((Date.now() - Date.parse(d.week)) / 864e5), since_field: "first_issued", sort: "first_issued", order: "asc" }) }),
      legend([[label("verdict", "likely"), VCOL.likely], [label("verdict", "possible"), VCOL.possible], [t("ov.weekly.legend_lead"), VCOL.lead]]),
      h("p", { class: "faint", style: { "margin-top": "8px" } }, t("ov.weekly.note")));

    const crtRuns = o.collection.runs.filter((r) => r.source_id === "crtsh").slice(0, 30);
    const health = card(t("ov.health.title"), t("ov.health.hint"),
      crtRuns.length ? runStrip(crtRuns) : empty(t("ov.health.none")),
      last ? h("div", { style: { "margin-top": "10px" } }, kv([
        [t("ov.health.last"), h("span", {}, statusChip(last.status), " ", h("a", { href: `#/run?id=${last.id}` }, `#${last.id}`), ` · ${dt(last.started_at)} UTC · ${secs(last.duration_s)}`)],
        [t("ov.health.coverage"), h("span", {}, Object.entries(cov).sort().map(([k, c]) => tag(`${k}: ${label("coverage", c)}`, t(`coverage_text.${c}`))))],
      ])) : null);

    const dnsBar = h("div", {}, (() => {
      const keys = ["resolved", "nxdomain", "no_address", "failed", "unchecked"];
      const vals = { resolved: dns.resolved || 0, nxdomain: dns.nxdomain || 0, no_address: dns.no_address || 0, failed: (dns.temporary_failure || 0) + (dns.failure || 0) + (dns.timeout || 0), unchecked: dns.unchecked || 0 };
      const cols = { resolved: "var(--live)", nxdomain: "var(--gone)", no_address: "#4b5768", failed: "var(--fail)", unchecked: "var(--panel-3)" };
      const tot = Math.max(1, keys.reduce((a, k) => a + vals[k], 0));
      return [h("div", { class: "stack" }, keys.map((k) => { const sp = h("span", { style: { width: `${(vals[k] / tot) * 100}%`, background: cols[k] } }); tipOn(sp, () => h("div", {}, `${label("dns", k)}: ${n(vals[k])}`)); return sp; })),
        legend(keys.map((k) => [`${label("dns", k)} ${n(vals[k])}`, cols[k]]))];
    })());

    const recent = card(t("ov.recent.title"), t("ov.recent.hint"),
      table([
        { label: t("col.domain"), cls: "dom", cell: (r) => domLink(r.name) },
        { label: t("col.verdict"), cell: (r) => verdictChip(r.verdict) },
        { label: t("col.score"), cell: (r) => scoreBar(r.score, r.verdict) },
        { label: t("col.first_cert"), cell: (r) => h("span", { class: "mono nowrap" }, day(r.first_issued)) },
        { label: t("col.dns"), cell: (r) => dnsChip(r.dns) },
      ], o.recent, { onRow: (r) => go("domain", { name: r.name }) }),
      h("div", { style: { "margin-top": "8px" } }, h("a", { href: "#/domains?sort=first_seen" }, t("ov.recent.all"))));

    const brands = card(t("ov.brands.title"), t("ov.brands.hint"),
      o.brands.length ? hbars(o.brands, ["likely", "possible"], { likely: VCOL.likely, possible: VCOL.possible }, (r) => brandLabel(r.brand), (r) => `#/domains?brand=${encodeURIComponent(r.brand)}&verdict=likely,possible`) : empty(t("ov.brands.none")));
    const camps = card(t("ov.camps.title"), t("ov.camps.hint"),
      o.top_campaigns.length ? table([
        { label: t("col.campaign"), cell: (r) => campLink(r.id) },
        { label: t("col.tier"), cell: (r) => tierChip(r.tier) },
        { label: t("col.names"), num: true, cell: (r) => n(r.size) },
        { label: t("col.brands"), cell: (r) => r.brands.map(brandTag) },
      ], o.top_campaigns, { onRow: (r) => go("campaign", { id: r.id }) }) : empty(t("empty.campaigns")));

    return h("div", {},
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, t("ov.title")), h("p", {}, t("ov.intro")))),
      kpis,
      h("div", { class: "grid g-main" }, weekly, health),
      h("div", { class: "grid g-main", style: { "margin-top": "14px" } }, recent,
        h("div", { class: "grid" }, card(t("ov.dns.title"), t("ov.dns.hint"), dnsBar), brands, camps)));
  };
  PAGES.analysis.titleKey = "nav.overview";
  function kpi(k, v, sub, color, href) {
    return h("a", { class: "kpi", href, style: { "--kc": color, color: "inherit", "text-decoration": "none" } },
      h("div", { class: "k" }, k), h("div", { class: "v" }, v), h("div", { class: "s" }, sub));
  }

  // domains --------------------------------------------------------------------
  PAGES.domains = async function domains(params) {
    const st = {
      q: params.get("q") || "", verdict: params.get("verdict") || "likely,possible,lead",
      brand: params.get("brand") || "", dns: params.get("dns") || "",
      since_days: params.get("since_days") || "", since_field: params.get("since_field") || "first_seen",
      campaign: params.get("campaign") || "", sort: params.get("sort") || "score",
      order: params.get("order") || "desc", offset: Number(params.get("offset") || 0),
    };
    const data = await api("domains", { ...st, limit: 100 });
    const upd = (patch) => go("domains", { ...st, offset: 0, ...patch });
    const vset = new Set(st.verdict.split(",").filter(Boolean));
    const vbtn = (v) => h("button", { class: vset.has(v) ? "on" : null, "aria-pressed": vset.has(v) ? "true" : "false", title: label("verdict_text", v), onclick: () => {
      vset.has(v) ? vset.delete(v) : vset.add(v);
      upd({ verdict: [...vset].join(",") || "likely" });
    } }, label("verdict", v));
    let deb;
    const search = h("input", { class: "f", type: "search", value: st.q, placeholder: t("dom.filter_ph"), maxlength: "100", "aria-label": t("dom.filter_aria"),
      oninput: (e) => { clearTimeout(deb); deb = setTimeout(() => upd({ q: e.target.value.trim() }), 350); } });
    const sel = (name, opts, cur, aria) => h("select", { "aria-label": aria, onchange: (e) => upd({ [name]: e.target.value }) },
      opts.map(([val, lab]) => h("option", { value: val, selected: val === cur ? true : null }, lab)));
    const brands = Object.keys(META.brands).map((k) => [k, brandLabel(k)]).sort((a, b) => a[1].localeCompare(b[1], LANG));
    const sortBtn = (key, text) => h("button", { class: st.sort === key ? "on" : null, onclick: () => upd({ sort: key, order: st.sort === key && st.order === "desc" ? "asc" : "desc" }) },
      text, st.sort === key ? (st.order === "desc" ? " ↓" : " ↑") : "");
    const filters = h("div", { class: "filters" }, search,
      h("div", { class: "grp", role: "group", "aria-label": t("col.verdict") }, ["likely", "possible", "lead", "weak", "legitimate", "none"].map(vbtn)),
      sel("brand", [["", t("dom.all_brands")], ...brands], st.brand, t("col.brand")),
      sel("dns", [["", t("dom.any_dns")], ...["resolved", "nxdomain", "no_address", "failed", "unchecked"].map((k) => [k, label("dns", k)])], st.dns, t("col.dns")),
      sel("since_days", [["", t("dom.any_time")], ["7", t("dom.last_n_days", { n: 7 })], ["30", t("dom.last_n_days", { n: 30 })], ["90", t("dom.last_n_days", { n: 90 })], ["365", t("dom.last_year")]], st.since_days, t("dom.window_aria")),
      sel("since_field", [["first_seen", t("dom.by_collected")], ["first_issued", t("dom.by_issued")]], st.since_field, t("dom.field_aria")),
      h("label", { class: "tog" }, h("input", { type: "checkbox", checked: st.campaign === "yes" ? true : null, onchange: (e) => upd({ campaign: e.target.checked ? "yes" : "" }) }), t("dom.in_campaign")));
    const cols = [
      { label: sortBtn("name", t("col.domain")), cls: "dom", cell: (r) => domLink(r.name) },
      { label: t("col.verdict"), cell: (r) => verdictChip(r.verdict) },
      { label: sortBtn("score", t("col.score")), cell: (r) => scoreBar(r.score, r.verdict) },
      { label: t("col.brands"), cell: (r) => r.brands.map(brandTag) },
      { label: sortBtn("first_issued", t("col.first_cert")), cell: (r) => h("span", { class: "mono nowrap" }, day(r.first_issued)) },
      { label: sortBtn("first_seen", t("col.collected")), cell: (r) => h("span", { class: "mono nowrap", title: r.first_seen_at }, day(r.first_seen_at)) },
      { label: t("col.dns"), cell: (r) => h("span", { title: r.dns_at ? t("dom.checked_at", { at: dt(r.dns_at) }) : "" }, dnsChip(r.dns)) },
      { label: t("col.campaign"), cell: (r) => (r.campaign_id ? campLink(r.campaign_id) : h("span", { class: "faint" }, "–")) },
    ];
    return h("div", {},
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, t("nav.domains")), h("p", {}, t("dom.intro")))),
      filters, h("section", { class: "card flush" }, table(cols, data.rows, { onRow: (r) => go("domain", { name: r.name }), empty: t("dom.none") }),
        pager(data.total, st.offset, data.limit, () => go("domains", { ...st, offset: Math.max(0, st.offset - 100) }), () => go("domains", { ...st, offset: st.offset + 100 }), t("pager.names"))));
  };
  PAGES.domains.titleKey = "nav.domains";

  // domain detail ----------------------------------------------------------------
  PAGES.domain = async function domain(params) {
    const d = await api("domain", { name: params.get("name") || "" });
    const dec = d.decision;
    const lastDns = d.dns[0];
    const pts = d.signals.filter((x) => x.points > 0);
    const totalPts = pts.reduce((a, x) => a + x.points, 0);
    const scoreStack = h("div", { class: "stack", role: "img", "aria-label": t("dd.score_aria") }, pts.map((x, i) => {
      const sp = h("span", { style: { width: `${(x.points / Math.max(100, totalPts)) * 100}%`, background: x.corroborating ? "var(--likely)" : "var(--indigo)", opacity: 1 - i * 0.07, "animation-delay": `${i * 40}ms` } });
      tipOn(sp, () => h("div", {}, h("b", {}, `${x.rule} +${x.points}`), h("div", {}, tx(x.detail))));
      return sp;
    }));
    const why = card(t("dd.why"), dec ? t("dd.why_hint", { score: dec.score }) : "",
      dec ? h("div", {}, h("div", { class: "explain" }, h("b", {}, `${label("verdict", dec.verdict)}: `), `${label("verdict_text", dec.verdict)}.`,
        dec.verdict === "likely" || dec.verdict === "possible" ? ` ${t("dd.brand_alone")}` : ""),
      pts.length ? scoreStack : null,
      d.signals.length ? d.signals.map((x) => h("div", { class: "sigrow" },
        h("span", { class: "pts", style: { color: x.points ? (x.corroborating ? "var(--likely)" : "var(--indigo)") : "var(--faint)" } }, x.points ? `+${x.points}` : "0"),
        h("span", { class: "rule", title: label("rule", x.rule) }, x.rule, x.corroborating ? h("span", { class: "faint", title: t("dd.corroborating") }, " ●") : null),
        h("span", { class: "det" }, h("b", {}, tx(x.detail)), h("br"), label("rule", x.rule)))) : empty(t("dd.no_signals"))) : empty(t("dd.not_scored")));

    const certs = card(t("dd.certs"), t("dd.certs_hint", { n: d.certificates.length }),
      table([
        { label: t("col.issued"), cell: (c) => h("a", { class: "mono nowrap", href: `#/certificate?id=${c.id}` }, day(c.not_before)) },
        { label: t("col.expires"), cell: (c) => h("span", { class: "mono nowrap faint" }, day(c.not_after)) },
        { label: t("col.issuer"), cell: (c) => h("span", { title: c.issuer_name }, issuerShort(c.issuer_name)) },
        { label: t("col.names"), num: true, cell: (c) => n(c.names) },
        { label: t("col.listed_as"), cell: (c) => [c.wildcard ? tag(t("cert.wildcard")) : null, (c.via || "").split(",").map((x) => tag(label("via", x)))] },
        { label: "crt.sh", cell: (c) => c.crtsh_ids.slice(0, 2).map((i) => h("div", {}, crtLink(i))) },
      ], d.certificates, { onRow: (c) => go("certificate", { id: c.id }) }));

    const accepted = d.relationships.filter((r) => r.accepted);
    const rejected = d.relationships.filter((r) => !r.accepted);
    const relTable = (rows) => table([
      { label: t("col.related"), cls: "dom", cell: (r) => domLink(r.a === d.domain.name ? r.b : r.a) },
      { label: t("col.strength"), cell: (r) => tierChip(r.strength) },
      { label: t("col.weight"), num: true, cell: (r) => h("span", { class: "mono" }, dec2(r.weight)) },
      { label: t("col.evidence"), cell: (r) => h("div", { class: "ev" }, r.evidence.map((e) => tag(`${label("kind", e.kind)}: ${e.value}`, t("ev.tip", { cls: label("class", e.class), df: e.df, w: dec2(e.weight) })))) },
      { label: t("col.decision"), cell: (r) => h("span", { class: "muted" }, tx(r.reason)) },
    ], rows, { rowClass: (r) => (r.accepted ? "relrow" : "relrow rej") });
    const rels = card(t("dd.related"), t("dd.related_hint", { a: accepted.length, r: rejected.length }),
      accepted.length ? relTable(accepted) : empty(t("dd.no_related")),
      rejected.length ? h("details", { style: { "margin-top": "10px" } }, h("summary", { class: "muted" }, t("dd.show_rejected", { n: rejected.length })), relTable(rejected)) : null);

    const status = card(t("dd.status"), null, kv([
      [t("dd.registrable"), h("span", { class: "mono" }, d.domain.registrable)],
      [t("dd.collected_first"), h("span", {}, h("span", { class: "mono" }, dt(d.domain.first_seen_at)), " UTC ", h("span", { class: "faint" }, `(${ago(d.domain.first_seen_at)})`))],
      [t("dd.first_cert"), h("span", { class: "mono" }, day(dec?.first_issued))],
      [t("dd.dns_now"), lastDns ? h("span", {}, dnsChip(lastDns.outcome), h("span", { class: "faint" }, ` ${t("dd.checked_at", { at: dt(lastDns.checked_at) })}`)) : dnsChip(null)],
      lastDns?.addresses?.length ? [t("dd.addresses"), addrList(lastDns.addresses)] : null,
      [t("col.campaign"), d.campaign ? h("span", {}, campLink(d.campaign.id), " ", tierChip(d.campaign.tier), h("span", { class: "faint" }, ` ${t("dd.campaign_size", { n: d.campaign.size })}`)) : h("span", { class: "faint" }, t("dd.no_campaign"))],
    ]));
    const dnsHist = card(t("dd.dns_hist"), t("dd.dns_hist_hint", { n: d.dns.length }),
      d.dns.length ? table([
        { label: t("col.checked_utc"), cell: (o) => h("span", { class: "mono nowrap" }, dt(o.checked_at)) },
        { label: t("col.outcome"), cell: (o) => dnsChip(o.outcome) },
        { label: t("dd.addresses"), cell: (o) => addrList(o.addresses) },
        { label: t("col.run"), cell: (o) => h("a", { href: `#/run?id=${o.run_id}` }, `#${o.run_id}`) },
      ], d.dns) : empty(t("dd.no_dns")));
    const av = d.availability, as = av.summary;
    const prots = [...new Set(av.history.map((o) => o.protection).filter(Boolean))];
    const availCard = card(t("dd.avail"), t("dd.avail_hint", { n: as.checks }),
      kv([
        [t("reg.f.state"), h("span", {}, availChip(as.state), as.last_state && !PUBLIC_OF[as.last_state] ? h("span", { class: "faint" }, ` · ${label("avail.state", as.last_state)}`) : null)],
        [t("reg.f.last_checked"), as.last_checked ? h("span", { class: "mono" }, `${dt(as.last_checked)} UTC`) : t("reg.not_checked")],
        [t("reg.f.last_reachable"), as.last_reachable ? h("span", { class: "mono" }, `${dt(as.last_reachable)} UTC`) : t("reg.never_confirmed")],
        as.previous_reachable ? [t("dd.prev_reachable"), h("span", { class: "mono" }, `${dt(as.previous_reachable)} UTC`)] : null,
        as.checks ? [t("dd.avail_first"), h("span", { class: "mono" }, `${dt(as.first_checked)} UTC`)] : null,
        [t("dd.avail_counts"), t("dd.avail_counts_val", { n: n(as.checks), ok: n(as.reachable_checks), bad: n(as.failed_checks) })],
        prots.length ? [t("dd.protection"), prots.join(", ")] : null,
      ]),
      av.history.length ? h("div", { style: { "margin-top": "10px" } }, table([
        { label: t("col.checked_utc"), cell: (o) => h("span", { class: "mono nowrap" }, dt(o.checked_at)) },
        { label: "DNS", cell: (o) => label("dns", o.dns) },
        { label: "TCP", cell: (o) => (o.tcp ? `${label("avail.tcp", o.tcp)}${o.port ? ` :${o.port}` : ""}` : "–") },
        { label: "TLS", cell: (o) => (o.tls ? label("avail.tls", o.tls) : "–") },
        { label: "HTTP", cell: (o) => (o.http_status ?? (o.http ? label("avail.http", o.http) : "–")) },
        { label: t("dd.av.protection"), cell: (o) => protText(o) },
        { label: t("dd.av.result"), cell: (o) => h("span", {}, stateChip(o.state), o.run_status === "failed" ? h("span", { class: "faint", title: t("dd.av.failed_run") }, " *") : null) },
        { label: t("dd.av.reason"), cell: (o) => h("span", { class: "muted" }, reasonText(o), o.location ? h("span", { class: "mono faint break", style: { display: "block" } }, `→ ${o.location}`) : null) },
      ], av.history)) : empty(av.in_registry ? t("dd.avail_none") : t("dd.avail_not_registry")),
      h("p", { class: "faint", style: { "margin-top": "8px" } }, t("dd.avail_semantics")));
    const inds = card(t("dd.indicators"), t("dd.indicators_hint"),
      d.indicators.length ? table([
        { label: t("col.kind"), cell: (i) => kindLabel(i.kind) },
        { label: t("col.value"), cell: (i) => h("span", { class: "mono break" }, i.value) },
        { label: t("col.class"), cell: (i) => label("class", i.class) },
        { label: "df", num: true, title: t("col.df_title"), cell: (i) => n(i.df) },
        { label: t("col.weight"), num: true, cell: (i) => h("span", { class: i.status === "active" ? "mono" : "mono faint", title: label("indstatus", i.status) }, i.status === "active" ? dec2(i.weight) : label("indstatus", i.status)) },
      ], d.indicators) : empty(t("dd.no_indicators")));
    const prov = card(t("dd.provenance"), t("dd.provenance_hint"),
      table([
        { label: t("col.record"), cell: (r) => h("span", { class: "mono" }, `#${r.id}`) },
        { label: "crt.sh", cell: (r) => crtLink(r.crtsh_id) },
        { label: t("col.query"), cell: (r) => h("span", { class: "mono" }, r.query) },
        { label: t("col.run"), cell: (r) => h("a", { href: `#/run?id=${r.run_id}` }, `#${r.run_id}`) },
        { label: t("col.fetched_utc"), cell: (r) => h("span", { class: "mono nowrap" }, dt(r.fetched_at)) },
        { label: t("col.payload_sha"), cell: (r) => h("span", { class: "mono", title: r.payload_sha256 }, short(r.payload_sha256, 16)) },
      ], d.records),
      h("p", { class: "faint", style: { "margin-top": "8px" } }, t("dd.scored_by", { rules: d.provenance.rules_version, id: d.provenance.analysis_id, asof: dt(d.provenance.as_of), sha: short(d.provenance.dataset_sha256, 16) })));

    return h("div", {},
      h("div", { class: "hero" }, h("h1", {}, d.domain.name), dec ? verdictChip(dec.verdict) : null,
        dec ? h("span", { class: "score", style: { color: VCOL[dec.verdict] } }, dec.score) : null,
        dec ? dec.brands.map(brandTag) : null),
      h("div", { class: "grid g-main" }, why, h("div", { class: "grid" }, status, dnsHist)),
      h("div", { class: "grid", style: { "margin-top": "14px" } }, availCard, rels, h("div", { class: "grid g2" }, certs, inds), prov));
  };
  PAGES.domain.titleKey = "page.domain";
  PAGES.domain.crumbs = (p) => [h("a", { href: "#/domains" }, t("nav.domains")), p.get("name") || ""];

  // certificates ---------------------------------------------------------------
  PAGES.certificates = async function certificates(params) {
    const st = { q: params.get("q") || "", flagged: params.get("flagged") || "yes", offset: Number(params.get("offset") || 0) };
    const data = await api("certificates", { ...st, limit: 100 });
    let deb;
    const upd = (patch) => go("certificates", { ...st, offset: 0, ...patch });
    const filters = h("div", { class: "filters" },
      h("input", { class: "f", type: "search", value: st.q, placeholder: t("cert.filter_ph"), maxlength: "100", "aria-label": t("cert.filter_aria"),
        oninput: (e) => { clearTimeout(deb); deb = setTimeout(() => upd({ q: e.target.value.trim() }), 350); } }),
      h("div", { class: "grp" }, [["yes", t("cert.with_flagged")], ["all", t("cert.all")]].map(([k, l]) => h("button", { class: st.flagged === k ? "on" : null, onclick: () => upd({ flagged: k }) }, l))));
    return h("div", {},
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, t("nav.certificates")), h("p", {}, t("cert.intro")))),
      filters,
      h("section", { class: "card flush" }, table([
        { label: t("col.issued"), cell: (c) => h("a", { class: "mono nowrap", href: `#/certificate?id=${c.id}` }, day(c.not_before)) },
        { label: t("col.issuer"), cell: (c) => h("span", { title: c.issuer_name }, issuerShort(c.issuer_name)) },
        { label: t("col.serial"), cell: (c) => h("span", { class: "mono", title: c.serial }, short(c.serial, 14)) },
        { label: t("col.names_seen"), num: true, cell: (c) => n(c.names) },
        { label: t("col.flagged_names"), cls: "dom", cell: (c) => c.flagged_names.slice(0, 3).map((x) => h("div", {}, domLink(x))) },
        { label: t("col.max_score"), num: true, cell: (c) => (c.max_score === null ? "–" : h("span", { class: "mono" }, c.max_score)) },
        { label: t("col.collected"), cell: (c) => h("span", { class: "mono nowrap faint" }, day(c.first_seen_at)) },
      ], data.rows, { onRow: (c) => go("certificate", { id: c.id }), empty: t("cert.none") }),
      pager(data.total, st.offset, 100, () => go("certificates", { ...st, offset: Math.max(0, st.offset - 100) }), () => go("certificates", { ...st, offset: st.offset + 100 }), t("pager.certs"))));
  };
  PAGES.certificates.titleKey = "nav.certificates";

  PAGES.certificate = async function certificate(params) {
    const d = await api("certificate", { id: params.get("id") || "" });
    const c = d.certificate;
    return h("div", {},
      h("div", { class: "hero" }, h("h1", {}, t("cert.hero", { serial: short(c.serial, 20) })), tag(issuerShort(c.issuer_name))),
      h("div", { class: "grid g-main" },
        h("div", { class: "grid" },
          card(t("cert.names"), t("cert.names_hint"),
            table([
              { label: t("col.name"), cls: "dom", cell: (r) => domLink(r.name) },
              { label: t("col.listed_as"), cell: (r) => [r.wildcard ? tag(t("cert.wildcard")) : null, tag(label("via", r.via))] },
              { label: t("col.verdict"), cell: (r) => (r.verdict ? verdictChip(r.verdict) : "–") },
              { label: t("col.score"), cell: (r) => (r.score === null ? "–" : scoreBar(r.score, r.verdict)) },
            ], d.names)),
          card(t("cert.records"), t("cert.records_hint"),
            d.records.map((r) => h("div", { style: { "margin-bottom": "12px" } },
              h("div", { class: "muted", style: { "margin-bottom": "4px" } }, t("cert.record_line", { id: r.id }), " · ", crtLink(r.crtsh_id), ` · ${t("col.query").toLowerCase()} `, h("span", { class: "mono" }, r.query), ` · ${t("col.run").toLowerCase()} `, h("a", { href: `#/run?id=${r.run_id}` }, `#${r.run_id}`), ` · sha256 ${short(r.payload_sha256, 16)}`),
              h("pre", { class: "mono", style: { margin: 0, padding: "10px", background: "var(--bg-2)", border: "1px solid var(--line)", "border-radius": "6px", overflow: "auto", "white-space": "pre-wrap", "word-break": "break-all" } }, JSON.stringify(r.payload, null, 2)))))),
        card(t("cert.card"), null, kv([
          [t("col.issuer"), h("span", { class: "break" }, c.issuer_name)],
          [t("col.serial"), h("span", { class: "mono break" }, c.serial)],
          [t("cert.key"), h("span", { class: "mono break" }, c.cert_key)],
          [t("cert.cn"), h("span", { class: "mono break" }, c.common_name || "–")],
          [t("cert.not_before"), h("span", { class: "mono" }, dt(c.not_before))],
          [t("cert.not_after"), h("span", { class: "mono" }, dt(c.not_after))],
          [t("cert.first_collected"), h("span", { class: "mono" }, `${dt(c.first_seen_at)} UTC`)],
        ]))));
  };
  PAGES.certificate.titleKey = "page.certificate";
  PAGES.certificate.crumbs = (p) => [h("a", { href: "#/certificates" }, t("nav.certificates")), `#${p.get("id")}`];

  // campaigns ----------------------------------------------------------------------
  PAGES.campaigns = async function campaigns(params) {
    const tier = params.get("tier") || "";
    const d = await api("campaigns", { tier });
    return h("div", {},
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, t("camp.title")), h("p", {}, t("camp.intro")))),
      h("div", { class: "filters" }, h("div", { class: "grp" }, [["", t("camp.all_tiers")], ["strong", label("tier", "strong")], ["corroborated", label("tier", "corroborated")], ["chained", label("tier", "chained")]].map(([k, l]) =>
        h("button", { class: tier === k ? "on" : null, title: k ? label("tier_text", k) : "", onclick: () => go("campaigns", { tier: k }) }, l)))),
      h("section", { class: "card flush" }, table([
        { label: t("col.campaign"), cell: (r) => campLink(r.id) },
        { label: t("col.tier"), cell: (r) => tierChip(r.tier) },
        { label: t("col.names"), num: true, cell: (r) => n(r.size) },
        { label: t("col.links"), num: true, cell: (r) => n(r.edges) },
        { label: t("col.density"), num: true, title: t("col.density_title"), cell: (r) => h("span", { class: "mono" }, dec2(r.density)) },
        { label: t("col.cohesion"), num: true, title: t("col.cohesion_title"), cell: (r) => h("span", { class: "mono" }, dec2(r.cohesion)) },
        { label: t("col.brands"), cell: (r) => r.brands.map(brandTag) },
        { label: t("col.issued"), cell: (r) => h("span", { class: "mono nowrap" }, `${day(r.first_issued)} → ${day(r.last_issued)}`) },
        { label: t("col.members"), cls: "dom", cell: (r) => h("span", { class: "muted" }, r.members.slice(0, 3).join(", "), r.members.length > 3 ? ` +${r.members.length - 3}` : "") },
      ], d.rows, { onRow: (r) => go("campaign", { id: r.id }), empty: t("empty.campaigns") })),
      h("p", { class: "faint", style: { "margin-top": "10px" } }, t("camp.settings", { edge: d.config.min_edge, kinds: d.config.min_kinds, nonweak: d.config.require_non_weak ? t("word.yes") : t("word.no") })));
  };
  PAGES.campaigns.titleKey = "nav.campaigns";

  PAGES.campaign = async function campaign(params) {
    const d = await api("campaign", { id: params.get("id") || "" });
    const c = d.campaign;
    const evBox = h("div", { class: "evbox" }, h("p", { class: "muted" }, t("cd.select")));
    const showEdge = (e) => {
      evBox.replaceChildren(h("h3", { style: { "margin-bottom": "6px" } }, domLink(e.a), " ↔ ", domLink(e.b)),
        h("p", {}, tierChip(e.strength), ` ${t("col.weight").toLowerCase()} ${dec2(e.weight)} · ${tx(e.reason)}`),
        table([
          { label: t("col.indicator"), cell: (x) => kindLabel(x.kind) },
          { label: t("col.shared_value"), cell: (x) => h("span", { class: "mono break" }, x.value) },
          { label: t("col.class"), cell: (x) => label("class", x.class) },
          { label: t("col.shared_by"), num: true, title: t("col.df_title"), cell: (x) => n(x.df) },
          { label: t("col.weight"), num: true, cell: (x) => h("span", { class: "mono" }, `+${dec2(x.weight)}`) },
        ], e.evidence));
    };
    const showNode = (m) => {
      const mine = d.edges.filter((e) => e.a === m.name || e.b === m.name);
      evBox.replaceChildren(h("h3", { style: { "margin-bottom": "6px" } }, domLink(m.name)),
        h("p", {}, verdictChip(m.verdict), ` ${t("col.score").toLowerCase()} ${m.score} · ${t("dd.first_cert").toLowerCase()} ${day(m.first_issued)} · `, dnsChip(m.dns)),
        h("p", { class: "muted" }, t("cd.node_links", { n: mine.length })));
    };
    const graph = forceGraph(d.members, d.edges, showEdge, showNode);
    const tl = memberTimeline(d.members);
    return h("div", {},
      h("div", { class: "hero" }, h("h1", {}, c.id), tierChip(c.tier),
        h("span", { class: "muted" }, t("cd.stats", { size: c.size, edges: c.edges, density: dec2(c.density), cohesion: dec2(c.cohesion), weakest: dec2(c.min_weight) }))),
      h("div", { class: `explain ${c.tier === "chained" ? "warn" : ""}` }, h("b", {}, `${label("tier", c.tier)}: `), label("tier_text", c.tier), " ", t("cd.hypothesis")),
      h("div", { class: "grid g-main" }, card(t("cd.graph"), t("cd.graph_hint"), graph), card(t("cd.evidence"), null, evBox)),
      h("div", { class: "grid", style: { "margin-top": "14px" } }, card(t("cd.timeline"), t("cd.timeline_hint"), tl),
        h("div", { class: "grid g2" },
          card(t("col.members"), null, table([
            { label: t("col.name"), cls: "dom", cell: (m) => domLink(m.name) },
            { label: t("col.verdict"), cell: (m) => verdictChip(m.verdict) },
            { label: t("col.score"), num: true, cell: (m) => h("span", { class: "mono" }, m.score) },
            { label: t("col.first_cert"), cell: (m) => h("span", { class: "mono nowrap" }, day(m.first_issued)) },
            { label: t("col.dns"), cell: (m) => dnsChip(m.dns) },
          ], d.members)),
          card(t("cd.shared"), t("cd.shared_hint"), table([
            { label: t("col.kind"), cell: (x) => kindLabel(x.kind) },
            { label: t("col.value"), cell: (x) => h("span", { class: "mono break" }, x.value) },
            { label: t("col.members"), num: true, cell: (x) => n(x.members) },
            { label: t("col.corpus_df"), num: true, title: t("col.corpus_df_title"), cell: (x) => n(x.df) },
            { label: t("col.weight"), num: true, cell: (x) => h("span", { class: x.status === "active" ? "mono" : "mono faint", title: label("indstatus", x.status) }, x.status === "active" ? dec2(x.weight) : label("indstatus", x.status)) },
          ], d.shared_indicators)))));
  };
  PAGES.campaign.titleKey = "page.campaign";
  PAGES.campaign.crumbs = (p) => [h("a", { href: "#/campaigns" }, t("nav.campaigns")), p.get("id") || ""];

  function forceGraph(members, edges, onEdge, onNode) {
    const N = members.length;
    const idx = new Map(members.map((m, i) => [m.name, i]));
    const pos = members.map((m, i) => ({ x: Math.cos((2 * Math.PI * i) / N) * 150, y: Math.sin((2 * Math.PI * i) / N) * 150, vx: 0, vy: 0 }));
    const E = edges.map((e) => ({ ...e, s: idx.get(e.a), t: idx.get(e.b) })).filter((e) => e.s !== undefined && e.t !== undefined);
    const ideal = N > 40 ? 60 : N > 12 ? 115 : 150;
    const repel = N > 12 ? 3200 : 1800;
    for (let it = 0; it < 320; it++) {
      const alpha = 1 - it / 320;
      for (let i = 0; i < N; i++) for (let j = i + 1; j < N; j++) {
        const dx = pos[j].x - pos[i].x, dy = pos[j].y - pos[i].y;
        const d2 = Math.max(25, dx * dx + dy * dy), f = (repel * alpha) / d2, d = Math.sqrt(d2);
        pos[i].vx -= (dx / d) * f; pos[i].vy -= (dy / d) * f; pos[j].vx += (dx / d) * f; pos[j].vy += (dy / d) * f;
      }
      for (const e of E) {
        const a = pos[e.s], b = pos[e.t];
        const dx = b.x - a.x, dy = b.y - a.y, d = Math.max(1, Math.hypot(dx, dy));
        const f = ((d - ideal / Math.sqrt(Math.max(1, e.weight / 3))) * 0.06) * alpha;
        a.vx += (dx / d) * f; a.vy += (dy / d) * f; b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
      }
      for (const p of pos) { p.vx -= p.x * 0.01 * alpha; p.vy -= p.y * 0.01 * alpha; p.x += p.vx; p.y += p.vy; p.vx *= 0.55; p.vy *= 0.55; }
    }
    const xs = pos.map((p) => p.x), ys = pos.map((p) => p.y);
    const pad = 70;
    // Never zoom in past 1:1 - the view box is at least the size of the panel, so
    // labels keep their real size on small campaigns.
    const cx = (Math.min(...xs) + Math.max(...xs)) / 2, cy = (Math.min(...ys) + Math.max(...ys)) / 2;
    const w = Math.max(Math.max(...xs) - Math.min(...xs) + 2 * pad + 260, 560);
    const hh = Math.max(Math.max(...ys) - Math.min(...ys) + 2 * pad, 380);
    let vb = { x: cx - w / 2, y: cy - hh / 2, w, h: hh };
    const svg = s("svg", { viewBox: `${vb.x} ${vb.y} ${vb.w} ${vb.h}`, role: "img", "aria-label": t("cd.graph_aria", { n: N }) });
    const setVB = () => svg.setAttribute("viewBox", `${vb.x} ${vb.y} ${vb.w} ${vb.h}`);
    const edgeEls = E.map((e) => {
      const col = e.strength === "strong" ? "var(--strong)" : "var(--corr)";
      const ln = s("line", { class: "edge", x1: pos[e.s].x, y1: pos[e.s].y, x2: pos[e.t].x, y2: pos[e.t].y, stroke: col, "stroke-width": 1 + Math.min(4, e.weight / 3), "stroke-opacity": 0.75 });
      ln.addEventListener("click", (ev) => { ev.stopPropagation(); select(ln); onEdge(e); });
      tipOn(ln, () => h("div", {}, h("b", {}, `${label("tier", e.strength)} · ${dec2(e.weight)}`), h("div", {}, e.kinds.map((k) => label("kind", k)).join(" + "))));
      return ln;
    });
    let selected = null;
    const select = (el) => { if (selected) selected.classList.remove("sel"); selected = el; el.classList.add("sel"); };
    const nodeEls = members.map((m, i) => {
      const r = 5 + (m.score / 100) * 6;
      const g = s("g", { class: "node", transform: `translate(${pos[i].x},${pos[i].y})`, tabindex: "0", role: "button", "aria-label": m.name },
        s("circle", { r, fill: VCOL[m.verdict] || "var(--weak)" }),
        N <= 12 ? s("text", pos[i].x < cx ? { x: -(r + 5), y: 3.5, "text-anchor": "end" } : { x: r + 5, y: 3.5 },
          m.name.length > 34 ? `${m.name.slice(0, 32)}…` : m.name) : null);
      const act = () => { select(g.firstChild); onNode(m); for (const [k, ln] of edgeEls.entries()) ln.setAttribute("stroke-opacity", E[k].a === m.name || E[k].b === m.name ? 1 : 0.15); };
      g.addEventListener("click", (ev) => { ev.stopPropagation(); act(); });
      g.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); act(); } });
      g.addEventListener("dblclick", () => go("domain", { name: m.name }));
      tipOn(g, () => h("div", {}, h("b", {}, m.name), h("div", {}, `${label("verdict", m.verdict)} · ${t("col.score").toLowerCase()} ${m.score}`), h("div", { class: "muted" }, t("cd.dblclick"))));
      return g;
    });
    svg.append(...edgeEls, ...nodeEls);
    svg.addEventListener("click", () => { for (const ln of edgeEls) ln.setAttribute("stroke-opacity", 0.75); });
    // pan & zoom
    svg.addEventListener("wheel", (ev) => {
      ev.preventDefault();
      const k = ev.deltaY > 0 ? 1.12 : 1 / 1.12;
      const r = svg.getBoundingClientRect();
      const mx = vb.x + ((ev.clientX - r.left) / r.width) * vb.w, my = vb.y + ((ev.clientY - r.top) / r.height) * vb.h;
      vb = { x: mx - (mx - vb.x) * k, y: my - (my - vb.y) * k, w: vb.w * k, h: vb.h * k };
      setVB();
    }, { passive: false });
    let drag = null;
    svg.addEventListener("pointerdown", (ev) => { if (ev.target === svg) drag = { x: ev.clientX, y: ev.clientY, vb: { ...vb } }; });
    addEventListener("pointerup", () => { drag = null; });
    svg.addEventListener("pointermove", (ev) => {
      if (!drag) return;
      const r = svg.getBoundingClientRect();
      vb.x = drag.vb.x - ((ev.clientX - drag.x) / r.width) * vb.w;
      vb.y = drag.vb.y - ((ev.clientY - drag.y) / r.height) * vb.h;
      setVB();
    });
    return h("div", { class: "graph-wrap" }, svg,
      h("div", { class: "graph-legend" }, h("span", {}, h("i", { style: { "border-color": "var(--strong)" } }), label("tier", "strong")), h("span", {}, h("i", { style: { "border-color": "var(--corr)" } }), label("tier", "corroborated")), h("span", { class: "faint" }, N > 12 ? t("cd.zoom_hint_labels") : t("cd.zoom_hint"))));
  }

  function memberTimeline(members) {
    const pts = members.filter((m) => m.first_issued).map((m) => ({ ...m, ts: Date.parse(m.first_issued.slice(0, 10)) }));
    if (!pts.length) return empty(t("cd.no_dates"));
    const W = 760, pad = 30, step = 7;
    const t0 = Math.min(...pts.map((p) => p.ts)), t1 = Math.max(...pts.map((p) => p.ts));
    const span = Math.max(864e5, t1 - t0);
    const x = (v) => pad + ((v - t0) / span) * (W - 2 * pad);
    // Same-day members stack upwards; the chart grows with the tallest stack.
    const counts = new Map();
    for (const p of pts) { const key = Math.round(x(p.ts) / 6); counts.set(key, (counts.get(key) || 0) + 1); }
    const base = 14 + Math.max(...counts.values()) * step;
    const H = base + 32;
    const svg = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": t("cd.timeline") },
      s("line", { class: "grid-l", x1: pad, x2: W - pad, y1: base, y2: base }),
      s("text", { x: pad, y: base + 26, "text-anchor": "start" }, new Date(t0).toISOString().slice(0, 10)),
      s("text", { x: W - pad, y: base + 26, "text-anchor": "end" }, new Date(t1).toISOString().slice(0, 10)));
    const stackAt = new Map();
    for (const p of pts) {
      const key = Math.round(x(p.ts) / 6);
      const k = stackAt.get(key) || 0; stackAt.set(key, k + 1);
      const c = s("circle", { cx: x(p.ts), cy: base - k * step, r: 3.5, fill: VCOL[p.verdict] || "var(--weak)", style: { cursor: "pointer" } });
      c.addEventListener("click", () => go("domain", { name: p.name }));
      tipOn(c, () => h("div", {}, h("b", {}, p.name), h("div", {}, `${t("dd.first_cert")}: ${day(p.first_issued)}`)));
      svg.append(c);
    }
    return svg;
  }

  // timeline -------------------------------------------------------------------------
  PAGES.timeline = async function timeline(params) {
    const days = params.get("days") || "90";
    const kind = params.get("kind") || "all";
    const d = await api("timeline", { days, kind });
    const cols = { issued: "var(--possible)", first_seen: "var(--accent)", dns_change: "var(--indigo)" };
    const byDay = new Map();
    for (const e of d.events) { const k = e.t.slice(0, 10); if (!byDay.has(k)) byDay.set(k, []); byDay.get(k).push(e); }
    const evDetail = (e) => {
      if (e.type === "first_seen") return t("tl.first_collected");
      if (e.type === "dns_change") {
        const [from, to] = String(e.detail || "").split(" -> ");
        return `${from === "first check" ? t("tl.first_check") : label("dns", from)} → ${label("dns", to)}`;
      }
      return issuerShort(e.detail);
    };
    const list = [...byDay.entries()].map(([k, evs]) => h("div", {}, h("div", { class: "timeline-day" }, t("tl.day_head", { day: k, n: evs.length })),
      evs.map((e) => h("div", { class: "tl-ev" }, h("span", { class: "tm" }, e.t.slice(11, 16) || "–"),
        h("span", { style: { color: cols[e.type] } }, h("span", { class: "dot" }), t(`tl.type.${e.type}`)),
        h("span", { class: "mono break" }, domLink(e.domain), " ", h("span", { class: "muted" }, evDetail(e))),
        verdictChip(e.verdict)))));
    return h("div", {},
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, t("nav.timeline")), h("p", {}, t("tl.intro")))),
      h("div", { class: "filters" },
        h("div", { class: "grp" }, [["7", t("tl.n_days", { n: 7 })], ["30", t("tl.n_days", { n: 30 })], ["90", t("tl.n_days", { n: 90 })], ["365", t("tl.one_year")]].map(([k, l]) => h("button", { class: days === k ? "on" : null, onclick: () => go("timeline", { days: k, kind }) }, l))),
        h("div", { class: "grp" }, ["all", "issued", "first_seen", "dns_change"].map((k) => h("button", { class: kind === k ? "on" : null, onclick: () => go("timeline", { days, kind: k }) }, t(`tl.filter.${k}`))))),
      card(t("tl.per_day"), t("tl.per_day_hint", { n: n(d.total), days: d.days }),
        stackedBars({ data: d.daily, keys: ["issued", "first_seen", "dns_change"], colors: cols, height: 130, aria: t("tl.per_day"),
          xlabel: (x, i) => (i % Math.max(1, Math.round(d.daily.length / 8)) === 0 ? x.day.slice(5) : ""),
          tipFor: (x) => h("div", {}, h("b", {}, x.day), h("div", {}, t("tl.tip", { issued: x.issued, seen: x.first_seen, dns: x.dns_change }))) }),
        legend(["issued", "first_seen", "dns_change"].map((k) => [t(`tl.type.${k}`), cols[k]]))),
      h("div", { style: { "margin-top": "14px" } }, card(t("tl.events"), d.total > d.events.length ? t("tl.newest", { shown: d.events.length, total: n(d.total) }) : null, d.events.length ? list : empty(t("tl.none")))));
  };
  PAGES.timeline.titleKey = "nav.timeline";

  // sources ------------------------------------------------------------------------
  PAGES.sources = async function sources() {
    const d = await api("sources");
    return h("div", {},
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, t("nav.sources")), h("p", {}, t("src.intro")))),
      h("div", { class: "grid g2" }, d.sources.map((x) => card(t(`source.${x.id}.name`), label("srckind", x.kind),
        h("p", {}, t(`source.${x.id}.description`)), h("p", { class: "muted" }, t(`source.${x.id}.provenance`)),
        kv([
          [t("src.endpoint"), h("span", { class: "mono break" }, x.endpoint)],
          [t("src.runs"), h("span", {}, n(x.runs), " ", Object.entries(x.status_counts).map(([k, v]) => h("span", { style: { "margin-left": "8px" } }, statusChip(k), ` ${v}`)))],
          [t("src.rate"), h("span", {}, pct(x.answer_rate_7d), h("span", { class: "faint" }, ` ${t("src.rate_note")}`))],
          [t("src.last_complete"), h("span", { class: "mono" }, x.last_complete ? `${dt(x.last_complete)} UTC` : t("word.never"))],
          [t("src.last_run"), x.last_run ? h("span", {}, statusChip(x.last_run.status), " ", h("a", { href: `#/run?id=${x.last_run.id}` }, `#${x.last_run.id}`), ` ${dt(x.last_run.started_at)} UTC`) : "–"],
          [t("src.records"), n(x.records)],
        ])))),
      h("div", { style: { "margin-top": "14px" } }, card(t("net.title"), t("net.hint"), networkTable(d.network))));
  };
  PAGES.sources.titleKey = "nav.sources";
  function networkTable(rows) {
    return table([
      { label: t("net.from"), cell: (r) => h("b", {}, t(`net.${r.id}.from`)) },
      { label: t("net.to"), cell: (r) => h("span", { class: "mono break" }, r.to) },
      { label: t("net.purpose"), cell: (r) => t(`net.${r.id}.purpose`) },
      { label: t("net.when"), cell: (r) => t(`net.${r.id}.when`) },
      { label: t("net.note"), cell: (r) => h("span", { class: "muted" }, t(`net.${r.id}.note`)) },
    ], rows);
  }

  // collection -----------------------------------------------------------------------
  PAGES.collection = async function collection(params) {
    const src = params.get("source") || "";
    const offset = Number(params.get("offset") || 0);
    const [runs, an] = await Promise.all([api("runs", { source: src, limit: 50, offset }), api("analyses")]);
    const crt = runs.rows.filter((r) => r.source_id === "crtsh");
    return h("div", {},
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, t("nav.collection")), h("p", {}, t("col.intro")))),
      crt.length ? card(t("col.outcomes"), t("col.outcomes_hint"), runStrip(crt.slice(0, 40))) : null,
      h("div", { class: "filters", style: { "margin-top": "14px" } }, h("div", { class: "grp" }, [["", t("col.all_sources")], ["crtsh", "crt.sh"], ["dns", "DNS"], ["availability", label("srcshort", "availability")]].map(([k, l]) => h("button", { class: src === k ? "on" : null, onclick: () => go("collection", { source: k }) }, l)))),
      h("section", { class: "card flush" }, table([
        { label: t("col.run"), cell: (r) => h("a", { href: `#/run?id=${r.id}` }, `#${r.id}`) },
        { label: t("col.source"), cell: (r) => label("srcshort", r.source_id) },
        { label: t("col.started_utc"), cell: (r) => h("span", { class: "mono nowrap" }, dt(r.started_at)) },
        { label: t("col.duration"), num: true, cell: (r) => secs(r.duration_s) },
        { label: t("col.status"), cell: (r) => statusChip(r.status) },
        { label: t("col.requested"), num: true, cell: (r) => n(r.queries_requested) },
        { label: t("col.answered"), num: true, cell: (r) => n(r.queries_ok) },
        { label: t("col.empty"), num: true, cell: (r) => n(r.queries_empty) },
        { label: t("col.abandoned"), num: true, cell: (r) => n(r.queries_abandoned) },
        { label: t("col.timeout"), num: true, cell: (r) => n(r.queries_timeout) },
        { label: t("col.failed"), num: true, cell: (r) => n(r.queries_failed) },
        { label: t("col.skipped"), num: true, cell: (r) => n(r.queries_skipped) },
        { label: t("col.records_new"), num: true, cell: (r) => `${n(r.records_received)} (${n(r.records_new)})` },
        { label: t("col.software"), cell: (r) => h("span", { class: "mono faint" }, r.software_version) },
      ], runs.rows, { onRow: (r) => go("run", { id: r.id }) }),
        pager(runs.total, offset, 50, () => go("collection", { source: src, offset: Math.max(0, offset - 50) }), () => go("collection", { source: src, offset: offset + 50 }), t("pager.runs"))),
      h("div", { class: "grid g2", style: { "margin-top": "14px" } },
        card(t("col.analyses"), t("col.analyses_hint"), table([
          { label: "#", cell: (a) => a.id },
          { label: t("col.asof_utc"), cell: (a) => h("span", { class: "mono nowrap" }, dt(a.as_of)) },
          { label: t("col.rules"), cell: (a) => h("span", { class: "mono" }, a.rules_version) },
          { label: t("col.dataset"), cell: (a) => h("span", { class: "mono", title: a.dataset_sha256 }, short(a.dataset_sha256)) },
          { label: t("col.results"), cell: (a) => h("span", { class: "mono", title: a.results_sha256 }, short(a.results_sha256)) },
          { label: t("col.flagged"), num: true, cell: (a) => n(a.domains_flagged) },
          { label: t("nav.campaigns"), num: true, cell: (a) => n(a.campaigns_total) },
        ], an.analyses)),
        card(t("col.snapshots"), t("col.snapshots_hint"), table([
          { label: t("col.created_utc"), cell: (x) => h("span", { class: "mono nowrap" }, dt(x.created_at)) },
          { label: t("col.analysis"), cell: (x) => `#${x.analysis_id}` },
          { label: t("col.dataset_sha"), cell: (x) => h("span", { class: "mono", title: x.dataset_sha256 }, short(x.dataset_sha256, 16)) },
          { label: t("col.file"), cell: (x) => h("span", { class: "mono break" }, x.file_name) },
          { label: t("col.size"), num: true, cell: (x) => bytes(x.bytes) },
        ], an.snapshots, { empty: t("col.no_snapshots") }))));
  };
  PAGES.collection.titleKey = "nav.collection";

  PAGES.run = async function run(params) {
    const d = await api("run", { id: params.get("id") || "" });
    const r = d.run;
    const cov = r.note?.coverage;
    const isCrt = r.source_id === "crtsh";
    const isAv = r.source_id === "availability";
    return h("div", {},
      h("div", { class: "hero" }, h("h1", {}, t("run.hero", { id: r.id })), statusChip(r.status), h("span", { class: "muted" }, `${label("srcshort", r.source_id)} · ${dt(r.started_at)} UTC · ${secs(r.duration_s)} · trawl ${r.software_version}`)),
      h("div", { class: "grid g-main" },
        isCrt ? card(t("run.queries"), t("run.queries_hint", { n: d.queries.length }), table([
          { label: t("col.keyword"), cell: (q) => h("span", { class: "mono" }, q.keyword) },
          { label: t("col.role"), cell: (q) => label("role", q.role) },
          { label: t("col.pattern"), cell: (q) => h("span", { class: "mono" }, q.query) },
          { label: t("col.outcome"), cell: (q) => h("span", { class: "nowrap", style: { color: OUTCOME_COL[q.outcome] }, title: q.outcome }, h("span", { class: "dot" }), label("outcome", q.outcome)) },
          { label: "HTTP", num: true, cell: (q) => q.http_status ?? "–" },
          { label: t("col.tries"), num: true, cell: (q) => q.attempts },
          { label: t("col.time"), num: true, cell: (q) => secs(q.duration_s) },
          { label: t("col.bytes"), num: true, cell: (q) => bytes(q.bytes) },
          { label: t("col.records_new"), num: true, cell: (q) => (q.records === null ? "–" : `${n(q.records)} (${n(q.records_new)})`) },
          { label: t("col.note"), cell: (q) => h("span", { class: "muted" }, tx(q.error || "")) },
        ], d.queries)) : isAv ? card(t("run.avail"), t("run.avail_hint", { n: d.availability.length }), table([
          { label: t("col.name"), cls: "dom", cell: (o) => domLink(o.domain) },
          { label: t("dd.av.result"), cell: (o) => stateChip(o.state) },
          { label: "HTTP", num: true, cell: (o) => o.http_status ?? "–" },
          { label: t("dd.av.protection"), cell: (o) => protText(o) },
          { label: t("dd.av.reason"), cell: (o) => h("span", { class: "muted" }, reasonText(o)) },
        ], d.availability)) : card(t("run.dns"), t("run.dns_hint", { n: d.dns.length }), table([
          { label: t("col.name"), cls: "dom", cell: (o) => domLink(o.domain) },
          { label: t("col.outcome"), cell: (o) => dnsChip(o.outcome) },
          { label: t("dd.addresses"), cell: (o) => addrList(o.addresses) },
          { label: t("col.error"), cell: (o) => h("span", { class: "muted" }, tx(o.error || "")) },
        ], d.dns)),
        h("div", { class: "grid" },
          isAv ? card(t("run.summary"), null, kv([
            [t("col.requested"), n(r.queries_requested)],
            ...Object.entries(r.note?.states || {}).filter(([, v]) => v).map(([k, v]) => [label("avail.state", k), n(v)]),
            [t("run.skipped"), n(r.queries_skipped)],
            [t("run.finished"), h("span", { class: "mono" }, r.finished_at ? `${dt(r.finished_at)} UTC` : "–")],
          ])) : card(t("run.summary"), null, kv([
            [t("col.requested"), n(r.queries_requested)], [t("run.answered_records"), n(r.queries_ok)], [t("run.answered_empty"), n(r.queries_empty)],
            isCrt ? [t("run.abandoned"), n(r.queries_abandoned)] : null, [t("run.timeouts"), n(r.queries_timeout)], [t("col.failed"), n(r.queries_failed)],
            isCrt ? [t("run.skipped"), n(r.queries_skipped)] : null, [t("run.records_received"), n(r.records_received)], [t("run.records_new"), n(r.records_new)],
            [t("run.finished"), h("span", { class: "mono" }, r.finished_at ? `${dt(r.finished_at)} UTC` : "–")],
          ])),
          cov ? card(t("run.coverage"), t("run.coverage_hint"), h("div", {}, Object.entries(cov).sort().map(([k, c]) => h("div", { class: "hbar wide-lab" }, h("span", { class: "mono" }, k), h("span", { class: "track" }, h("span", { style: { width: c === "full" ? "100%" : c === "partial" ? "50%" : "4%", background: c === "full" ? "var(--live)" : c === "partial" ? "var(--possible)" : "var(--likely)" } })), h("span", { class: "muted", title: t(`coverage_text.${c}`) }, label("coverage", c)))))) : null,
          card(t("run.config"), t("run.config_hint"), h("pre", { class: "mono", style: { margin: 0, "white-space": "pre-wrap", "word-break": "break-all", color: "var(--text-2)" } }, JSON.stringify(r.config_json, null, 2))))));
  };
  PAGES.run.titleKey = "page.run";
  PAGES.run.crumbs = (p) => [h("a", { href: "#/collection" }, t("nav.collection")), t("run.hero", { id: p.get("id") })];

  // methodology -------------------------------------------------------------------------
  PAGES.methodology = async function methodology() {
    const m = await api("methodology");
    const p = m.provenance;
    const corr = m.correlation;
    const list = (arr) => h("div", { class: "ev" }, arr.map((x) => tag(x)));
    const items = (prefix, count) => Array.from({ length: count }, (_, i) => h("li", {}, t(`${prefix}.${i + 1}`)));
    return h("div", { class: "prose" },
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, t("meth.title")), h("p", {}, t("meth.intro")))),
      h("div", { class: "explain warn" }, h("b", {}, `${t("disclaimer.title")} `), t("disclaimer.body")),
      h("h3", {}, t("meth.does")), h("ol", {}, items("meth.does", 6)),
      h("h3", {}, t("meth.cannot")), h("ul", {}, items("meth.cannot", 4)),
      h("h3", {}, t("meth.terms")),
      table([{ label: t("meth.term"), cell: (g) => h("b", {}, t(`glossary.${g.id}.term`)) }, { label: t("meth.meaning"), cell: (g) => t(`glossary.${g.id}.text`) }], m.glossary),
      h("h3", {}, t("meth.rules", { v: m.rules_version })),
      table([
        { label: t("col.rule"), cell: (r) => h("span", { class: "mono" }, r.id) },
        { label: t("col.points"), num: true, cell: (r) => h("span", { class: "mono" }, r.points) },
        { label: t("col.corroborating"), cell: (r) => (r.corroborating ? t("word.yes") : "–") },
        { label: t("meth.meaning"), cell: (r) => label("rule", r.id) },
      ], m.rules),
      h("p", { class: "muted", style: { "margin-top": "8px" } }, t("meth.thresholds", { likely: m.thresholds.likely, possible: m.thresholds.possible, days: m.recent_days })),
      table([{ label: t("col.verdict"), cell: (v) => verdictChip(v.id) }, { label: t("meth.meaning"), cell: (v) => label("verdict_text", v.id) }], m.verdicts),
      h("h3", {}, t("meth.brands")),
      table([
        { label: t("col.brand"), cell: (b) => h("b", {}, brandLabel(b.id)) },
        { label: t("col.sector"), cell: (b) => label("sector", b.sector) },
        { label: t("col.match"), cell: (b) => (b.ambiguous ? h("span", { title: t("meth.ambiguous_title") }, t("meth.ambiguous")) : t("meth.distinctive")) },
        { label: t("col.phrases"), cell: (b) => list(b.phrases) },
        { label: t("col.keywords"), cell: (b) => list(b.query_keys) },
        { label: t("col.allowlisted"), cell: (b) => list(b.official) },
      ], m.brands),
      h("details", {}, h("summary", {}, t("meth.lists")),
        h("p", {}, h("b", {}, t("meth.namesakes"))), table([{ label: t("col.domain"), cell: (x) => h("span", { class: "mono" }, x[0]) }, { label: t("meth.why"), cell: (x) => tx(x[1]) }], Object.entries(m.namesakes)),
        h("p", {}, h("b", {}, t("meth.tld_high"))), list(m.tld_high), h("p", {}, h("b", {}, t("meth.tld_moderate"))), list(m.tld_moderate),
        h("p", {}, h("b", {}, t("meth.lures_bg"))), list(m.lures_bg), h("p", {}, h("b", {}, t("meth.lures_en"))), list(m.lures_en),
        h("p", {}, h("b", {}, t("meth.markers"))), list(m.bg_markers)),
      h("h3", {}, t("meth.correlation")),
      h("p", {}, t("meth.corr_text", { pop: corr.population.map((x) => label("verdict", x)).join(", "), edge: corr.min_edge, kinds: corr.min_kinds, nonweak: corr.require_non_weak ? t("meth.corr_nonweak") : "", chained: corr.chained_density })),
      table([
        { label: t("col.indicator_kind"), cell: (r) => h("span", {}, label("kind", r[0]), " ", h("span", { class: "mono faint" }, r[0])) },
        { label: t("col.class"), cell: (r) => label("class", r[1].class) },
        { label: t("col.base_weight"), num: true, cell: (r) => r[1].base },
        { label: t("col.max_df"), num: true, cell: (r) => r[1].max_df },
      ], Object.entries(corr.kinds)),
      h("h3", {}, t("meth.provenance")),
      kv([
        [t("col.analysis"), t("meth.analysis_line", { id: p.analysis_id, created: dt(p.created_at), asof: dt(p.as_of) })],
        [t("col.software"), `trawl ${p.software_version}`], [t("col.rules"), p.rules_version],
        [t("meth.corr_sha"), h("span", { class: "mono break" }, p.correlation_sha256)],
        [t("col.dataset_sha"), h("span", { class: "mono break" }, p.dataset_sha256)],
        [t("meth.results_sha"), h("span", { class: "mono break" }, p.results_sha256)],
        [t("meth.cutoffs"), h("span", { class: "mono" }, t("meth.cutoffs_line", { run: p.cutoffs.run, record: p.cutoffs.record, dns: p.cutoffs.dns }))],
      ]),
      h("p", { class: "muted", style: { "margin-top": "8px" } }, t("meth.reproduce")),
      h("h3", {}, t("meth.network")), networkTable(m.network),
      h("h3", {}, t("meth.independence")), h("p", {}, t("meth.independence_text")),
      h("h3", {}, t("meth.language")), h("p", {}, t("meth.language_text")));
  };
  PAGES.methodology.titleKey = "nav.methodology";

  async function notFound() { return h("div", { class: "errbox" }, t("error.no_page"), " ", h("a", { href: "#/" }, t("error.go_overview"))); }
  notFound.titleKey = "page.not_found";

  // ---------------------------------------------------------------- chrome + boot
  function fillProvenance() {
    if (!META) return;
    const p = META.provenance;
    document.getElementById("prov-chip").textContent = t("prov.chip", { id: p.analysis_id, asof: dt(p.as_of), sha: short(p.dataset_sha256, 10) });
    document.getElementById("prov-chip").title = t("prov.chip_title");
    document.getElementById("prov-side").replaceChildren(h("dl", {},
      h("dt", {}, t("prov.analysis")), h("dd", {}, `#${p.analysis_id}`),
      h("dt", {}, t("prov.asof")), h("dd", {}, `${dt(p.as_of)} UTC`),
      h("dt", {}, t("prov.rules")), h("dd", {}, p.rules_version),
      h("dt", {}, t("prov.dataset")), h("dd", { title: p.dataset_sha256 }, short(p.dataset_sha256, 16)),
      h("dt", {}, t("prov.results")), h("dd", { title: p.results_sha256 }, short(p.results_sha256, 16))));
  }
  function applyStatic() {
    document.documentElement.lang = LANG;
    for (const el of document.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
    for (const el of document.querySelectorAll("[data-i18n-placeholder]")) el.setAttribute("placeholder", t(el.dataset.i18nPlaceholder));
    for (const el of document.querySelectorAll("[data-i18n-aria]")) el.setAttribute("aria-label", t(el.dataset.i18nAria));
    for (const b of document.querySelectorAll(".langsw button")) b.setAttribute("aria-pressed", b.dataset.lang === LANG ? "true" : "false");
  }
  function setLang(lang) {
    if (!LANGS.includes(lang)) return;
    LANG = lang;
    try { localStorage.setItem("trawl.lang", lang); } catch { /* private mode: keep for this page */ }
    fmt = new Intl.NumberFormat(lang === "bg" ? "bg-BG" : "en-GB");
    applyStatic();
    buildNav();
    fillProvenance();
    if (META) render();
  }
  async function boot() {
    LANG = savedLang();
    try {
      const r = await fetch("/i18n.json", { credentials: "same-origin" });
      I18N = await r.json();
      PATTERNS = (I18N.patterns_bg || []).map(([re, rep]) => [new RegExp(re), rep]);
    } catch {
      I18N = { bg: {}, en: {} };
    }
    for (const b of document.querySelectorAll(".langsw button")) b.addEventListener("click", () => setLang(b.dataset.lang));
    fmt = new Intl.NumberFormat(LANG === "bg" ? "bg-BG" : "en-GB");
    applyStatic();
    buildNav();
    document.getElementById("jump").addEventListener("submit", (e) => {
      e.preventDefault();
      const q = document.getElementById("jump-q").value.trim().toLowerCase();
      if (q) go("", { q });
    });
    addEventListener("keydown", (e) => {
      if (e.key === "/" && !/^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement?.tagName)) { e.preventDefault(); document.getElementById("jump-q").focus(); }
    });
    try {
      META = await api("meta");
      fillProvenance();
    } catch (e) {
      view.replaceChildren(h("div", { class: "errbox" }, h("b", {}, t("error.no_analysis")), " ", h("p", { class: "muted" }, t("error.no_analysis_hint"))));
      return;
    }
    addEventListener("hashchange", render);
    render();
  }
  boot();
})();
