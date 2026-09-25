/* trawl investigation UI.
 * Security note: every piece of data reaches the DOM through textContent or
 * setAttribute on a fixed attribute name. There is no innerHTML, no eval, and the
 * only URLs built from data are same-origin hash routes (encodeURIComponent) and
 * crt.sh links built from integer ids.
 */
"use strict";
(() => {
  const SVGNS = "http://www.w3.org/2000/svg";
  const view = document.getElementById("view");
  const tip = document.getElementById("tip");
  let META = null;
  let renderToken = 0;

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
  const fmt = new Intl.NumberFormat("en-GB");
  const n = (x) => (x === null || x === undefined ? "–" : fmt.format(x));
  const pct = (x) => (x === null || x === undefined ? "–" : `${(x * 100).toFixed(x < 0.1 ? 1 : 0)}%`);
  const day = (iso) => (iso ? String(iso).slice(0, 10) : "–");
  const dt = (iso) => (iso ? String(iso).replace("T", " ").slice(0, 16) : "–");
  const short = (sha, k = 12) => (sha ? String(sha).slice(0, k) : "–");
  function ago(iso) {
    if (!iso) return "–";
    const t = Date.parse(String(iso).length <= 19 ? iso + "Z" : iso);
    if (Number.isNaN(t)) return "–";
    const d = (Date.now() - t) / 1000;
    if (d < 90) return "just now";
    if (d < 5400) return `${Math.round(d / 60)} min ago`;
    if (d < 172800) return `${Math.round(d / 3600)} h ago`;
    return `${Math.round(d / 86400)} d ago`;
  }
  const secs = (x) => (x === null || x === undefined ? "–" : x < 90 ? `${x.toFixed(0)} s` : x < 5400 ? `${(x / 60).toFixed(1)} min` : `${(x / 3600).toFixed(1)} h`);
  const bytes = (b) => (b === null || b === undefined ? "–" : b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(0)} kB` : `${(b / 1048576).toFixed(1)} MB`);

  const VCOL = { likely: "var(--likely)", possible: "var(--possible)", lead: "var(--lead)", weak: "var(--weak)", none: "var(--none)", legitimate: "var(--legit)" };
  const DNS_LABEL = { resolved: "resolving", nxdomain: "NXDOMAIN", no_address: "no address", temporary_failure: "lookup failed", failure: "lookup failed", timeout: "lookup timeout", unchecked: "not checked" };

  const chip = (cls, label, title) => h("span", { class: `chip ${cls}`, title }, label);
  const verdictChip = (v) => chip(`v-${v}`, v, META?.verdicts?.[v]);
  const dnsChip = (o) => { const k = o || "unchecked"; return h("span", { class: `nowrap d-${k}` }, h("span", { class: "dot" }), DNS_LABEL[k] || k); };
  const tierChip = (t) => chip(`t-${t}`, t);
  const statusChip = (st) => h("span", { class: `nowrap s-${st}` }, h("span", { class: "dot" }), st);
  const tag = (t, title) => h("span", { class: "tag", title }, t);
  const domLink = (name) => h("a", { href: `#/domain?name=${encodeURIComponent(name)}` }, name);
  const campLink = (id) => h("a", { class: "mono", href: `#/campaign?id=${encodeURIComponent(id)}` }, id);
  const crtLink = (id) => h("a", { href: `https://crt.sh/?id=${Number(id)}`, target: "_blank", rel: "noopener noreferrer", class: "mono", title: "Open this record on crt.sh (leaves this site)" }, `crt.sh/${Number(id)} ↗`);
  function scoreBar(score, verdict) {
    return h("span", { class: "scorebar" }, h("span", { class: "mono" }, score),
      h("i", {}, h("b", { style: { width: `${Math.max(2, score)}%`, "--c": VCOL[verdict] || "var(--accent)" } })));
  }
  function card(title, hint, ...body) {
    return h("section", { class: "card" }, h("header", {}, h("h2", {}, title), hint ? h("span", { class: "hint" }, hint) : null), ...body);
  }
  const empty = (msg) => h("div", { class: "empty" }, msg);
  function table(cols, rows, opts = {}) {
    const thead = h("thead", {}, h("tr", {}, cols.map((c) => h("th", { class: c.num ? "num" : null, title: c.title }, c.label))));
    const tbody = h("tbody", {}, rows.map((r) => {
      const tr = h("tr", { class: [opts.rowClass?.(r), opts.onRow ? "link" : null].filter(Boolean).join(" ") || null },
        cols.map((c) => h("td", { class: [c.num ? "num" : null, c.cls].filter(Boolean).join(" ") || null }, c.cell(r))));
      if (opts.onRow) tr.addEventListener("click", (e) => { if (!e.target.closest("a")) opts.onRow(r); });
      return tr;
    }));
    return h("div", { class: "tbl-wrap" }, h("table", {}, thead, tbody), rows.length ? null : empty(opts.empty || "Nothing to show."));
  }
  function kv(pairs) {
    return h("dl", { class: "kv" }, pairs.filter(Boolean).map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
  }

  // tooltips
  function tipOn(el, content) {
    el.addEventListener("mouseenter", () => { tip.replaceChildren(content()); tip.hidden = false; });
    el.addEventListener("mousemove", (e) => {
      const w = tip.offsetWidth, hgt = tip.offsetHeight;
      tip.style.left = `${Math.min(e.clientX + 14, innerWidth - w - 8)}px`;
      tip.style.top = `${Math.min(e.clientY + 14, innerHeight - hgt - 8)}px`;
    });
    el.addEventListener("mouseleave", () => { tip.hidden = true; });
  }

  // ---------------------------------------------------------------- api + routing
  async function api(path, params = {}) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") qs.set(k, v);
    const url = `/api/${path}${[...qs].length ? `?${qs}` : ""}`;
    const r = await fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" });
    let j;
    try { j = await r.json(); } catch { j = { error: `HTTP ${r.status}` }; }
    if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`);
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
    overview: "M3 3h6v8H3zM11 3h6v5h-6zM11 10h6v7h-6zM3 13h6v4H3z",
    domains: "M10 2a8 8 0 100 16 8 8 0 000-16zM2 10h16M10 2c2.5 2.2 3.5 5 3.5 8s-1 5.8-3.5 8c-2.5-2.2-3.5-5-3.5-8s1-5.8 3.5-8z",
    certificates: "M4 3h12v10H4zM7 7h6M7 10h4M8 13l-1 5 3-2 3 2-1-5",
    campaigns: "M5 5a2 2 0 110 .1M15 4a2 2 0 110 .1M10 14a2 2 0 110 .1M5 5l5 9M15 4l-5 10M5 5l10-1",
    timeline: "M3 10h14M6 6v8M10 4v12M14 7v6",
    sources: "M4 4h12v4H4zM4 12h12v4H4zM7 6h.1M7 14h.1",
    collection: "M3 16l4-6 3 3 4-7 3 4M3 3v14h14",
    methodology: "M5 3h8l3 3v11H5zM8 9h6M8 12h6M8 15h4",
  };
  const NAV = [["", "Overview", "overview"], ["domains", "Domains", "domains"], ["certificates", "Certificates", "certificates"],
    ["campaigns", "Campaigns", "campaigns"], ["timeline", "Timeline", "timeline"], null,
    ["sources", "Sources", "sources"], ["collection", "Collection", "collection"], ["methodology", "About / Methodology", "methodology"]];
  const SECTION_OF = { domain: "domains", certificate: "certificates", campaign: "campaigns", run: "collection" };

  function buildNav() {
    const nav = document.getElementById("nav");
    nav.replaceChildren(...NAV.map((item) => {
      if (!item) return h("div", { class: "sep" });
      const [path, label, icon] = item;
      return h("a", { href: `#/${path}`, "data-p": path },
        s("svg", { viewBox: "0 0 20 20", "aria-hidden": "true" }, s("path", { d: ICONS[icon], fill: "none", stroke: "currentColor", "stroke-width": "1.5", "stroke-linecap": "round", "stroke-linejoin": "round" })),
        label);
    }));
  }
  function setNav(path, crumbs) {
    const sec = SECTION_OF[path] ?? path;
    for (const a of document.querySelectorAll("#nav a")) a.classList.toggle("on", a.dataset.p === sec);
    const c = document.getElementById("crumbs");
    c.replaceChildren(...(crumbs || []).flatMap((x, i) => [i ? " / " : null, i === crumbs.length - 1 ? h("b", {}, x) : x]).filter((x) => x !== null));
  }

  async function render() {
    const { path, params } = parseHash();
    const page = PAGES[path] || notFound;
    const token = ++renderToken;
    setNav(path, [page.title || "trawl"]);
    view.replaceChildren(h("div", { class: "loading" }, "Loading"));
    try {
      const node = await page(params);
      if (token !== renderToken) return;
      view.replaceChildren(node);
      view.style.animation = "none"; void view.offsetWidth; view.style.animation = "";
      if (page.crumbs) setNav(path, page.crumbs(params));
      window.scrollTo(0, 0);
    } catch (e) {
      if (token !== renderToken) return;
      view.replaceChildren(h("div", { class: "errbox" }, h("b", {}, "Could not load this view. "), String(e.message || e)));
    }
  }

  // ---------------------------------------------------------------- charts
  function stackedBars({ data, keys, colors, height = 150, label, tipFor, onClick }) {
    const W = 760, H = height, padL = 30, padB = 18, padT = 6;
    const max = Math.max(1, ...data.map((d) => keys.reduce((a, k) => a + (d[k] || 0), 0)));
    const nice = niceMax(max);
    const bw = Math.min((W - padL) / Math.max(1, data.length), 34);   // few bars stay bars
    const y = (v) => H - padB - (v / nice) * (H - padB - padT);
    const svg = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img" });
    for (const t of [0, nice / 2, nice]) {
      svg.append(s("line", { class: "grid-l", x1: padL, x2: W, y1: y(t), y2: y(t) }));
      svg.append(s("text", { x: padL - 6, y: y(t) + 3, "text-anchor": "end" }, n(Math.round(t))));
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
      const lab = label?.(d, i);
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
    return h("div", { class: "legend" }, items.map(([label, color]) => h("span", {}, h("i", { style: { background: color } }), label)));
  }
  function hbars(rows, keys, colors, labelFor, hrefFor) {
    const max = Math.max(1, ...rows.map((r) => keys.reduce((a, k) => a + (r[k] || 0), 0)));
    return h("div", {}, rows.map((r, i) => {
      const tot = keys.reduce((a, k) => a + (r[k] || 0), 0);
      const lab = hrefFor ? h("a", { href: hrefFor(r) }, labelFor(r)) : labelFor(r);
      const row = h("div", { class: "hbar" }, h("span", { class: "nowrap", style: { overflow: "hidden", "text-overflow": "ellipsis" } }, lab),
        h("span", { class: "track" }, keys.map((k) => h("span", { style: { width: `${((r[k] || 0) / max) * 100}%`, background: colors[k], "animation-delay": `${i * 30}ms` } }))),
        h("span", { class: "num mono" }, n(tot)));
      tipOn(row, () => h("div", {}, h("b", {}, labelFor(r)), keys.map((k) => h("div", {}, `${k}: ${n(r[k] || 0)}`))));
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
      stackedBars({ data, keys: Object.keys(cols), colors: cols, height: 120,
        tipFor: (d) => h("div", {}, h("b", {}, `Run ${d.id} · ${d.status}`), h("div", {}, dt(d.started_at)),
          h("div", {}, `answered ${d.ok + d.empty} / ${d.queries_requested}`), d.abandoned ? h("div", {}, `abandoned by crt.sh: ${d.abandoned}`) : null,
          d.timeout ? h("div", {}, `timeouts: ${d.timeout}`) : null, d.failed ? h("div", {}, `failed: ${d.failed}`) : null),
        onClick: (d) => go("run", { id: d.id }) }),
      legend([["answered", cols.ok], ["answered: empty", cols.empty], ["abandoned scan", cols.abandoned], ["timeout", cols.timeout], ["failed", cols.failed], ["skipped (budget)", cols.skipped]]));
  }

  // ---------------------------------------------------------------- pages
  const PAGES = {};

  PAGES[""] = async function overview() {
    const o = await api("overview");
    const v = o.verdicts;
    const dns = o.dns || {};
    const checked = Object.entries(dns).filter(([k]) => k !== "unchecked").reduce((a, [, x]) => a + x, 0);
    const last = o.collection.last_crtsh;
    const cov = last?.note?.coverage || {};
    const covVals = Object.values(cov);
    const tiers = o.campaign_tiers || {};
    const kpis = h("div", { class: "kpis" },
      kpi("Flagged names", n(o.flagged), `${n(v.likely || 0)} likely · ${n(v.possible || 0)} possible · ${n(v.lead || 0)} leads`, "var(--likely)", "#/domains"),
      kpi("First certificate ≤ 30 d", n(o.issued_30d), "flagged names whose first certificate is recent", "var(--possible)", "#/domains?since_days=30&since_field=first_issued&sort=first_issued"),
      kpi("New to dataset · 7 d", n(o.new_7d), "first collected in the last 7 days", "var(--accent)", "#/domains?since_days=7&sort=first_seen"),
      kpi("Still resolving", n(dns.resolved || 0), `of ${n(checked)} DNS-checked · ${n(dns.unchecked || 0)} not yet checked`, "var(--live)", "#/domains?dns=resolved"),
      kpi("Campaign hypotheses", n(Object.values(tiers).reduce((a, x) => a + x, 0)), `${n(tiers.strong || 0)} strong · ${n(tiers.corroborated || 0)} corroborated · ${n(tiers.chained || 0)} chained`, "var(--corr)", "#/campaigns"),
      kpi("Last crt.sh run", last ? last.status : "none", last ? `${covVals.filter((x) => x === "full").length}/${covVals.length} keywords fully covered · ${ago(last.finished_at || last.started_at)}` : "no collection yet", last?.status === "complete" ? "var(--live)" : "var(--possible)", last ? `#/run?id=${last.id}` : "#/collection"));

    const weekly = card("Flagged certificate issuance", "first certificate per flagged name, by week · 52 weeks",
      stackedBars({ data: o.weekly_issuance, keys: ["likely", "possible", "lead"], colors: { likely: VCOL.likely, possible: VCOL.possible, lead: VCOL.lead },
        label: (d, i) => (i % 8 === 0 ? d.week.slice(2, 10) : ""),
        tipFor: (d) => h("div", {}, h("b", {}, `week of ${d.week}`), h("div", {}, `likely ${d.likely} · possible ${d.possible} · lead ${d.lead}`), h("div", { class: "muted" }, "click to list")),
        onClick: (d) => go("domains", { since_days: Math.ceil((Date.now() - Date.parse(d.week)) / 864e5), since_field: "first_issued", sort: "first_issued", order: "asc" }) }),
      legend([["likely", VCOL.likely], ["possible", VCOL.possible], ["lead (no brand)", VCOL.lead]]),
      h("p", { class: "faint", style: { "margin-top": "8px" } }, "Issuance date comes from the certificate itself (not_before), so backfilled history appears in the week it happened, not the week it was collected."));

    const crtRuns = o.collection.runs.filter((r) => r.source_id === "crtsh").slice(0, 30);
    const health = card("Collection health", "crt.sh runs · query outcomes",
      crtRuns.length ? runStrip(crtRuns) : empty("No crt.sh runs yet."),
      last ? h("div", { style: { "margin-top": "10px" } }, kv([
        ["Last run", h("span", {}, statusChip(last.status), " ", h("a", { href: `#/run?id=${last.id}` }, `#${last.id}`), ` · ${dt(last.started_at)} UTC · ${secs(last.duration_s)}`)],
        ["Coverage", h("span", {}, Object.entries(cov).sort().map(([k, c]) => tag(`${k}:${c}`, c === "full" ? "contains-pattern answered" : c === "partial" ? "only prefix/dotted answered" : "no pattern answered")))],
      ])) : null);

    const dnsBar = h("div", {}, (() => {
      const keys = ["resolved", "nxdomain", "no_address", "failed", "unchecked"];
      const vals = { resolved: dns.resolved || 0, nxdomain: dns.nxdomain || 0, no_address: dns.no_address || 0, failed: (dns.temporary_failure || 0) + (dns.failure || 0) + (dns.timeout || 0), unchecked: dns.unchecked || 0 };
      const cols = { resolved: "var(--live)", nxdomain: "var(--gone)", no_address: "#4b5768", failed: "var(--fail)", unchecked: "var(--panel-3)" };
      const tot = Math.max(1, keys.reduce((a, k) => a + vals[k], 0));
      return [h("div", { class: "stack" }, keys.map((k) => { const sp = h("span", { style: { width: `${(vals[k] / tot) * 100}%`, background: cols[k] } }); tipOn(sp, () => h("div", {}, `${k}: ${n(vals[k])}`)); return sp; })),
        legend(keys.map((k) => [`${k.replace("_", " ")} ${n(vals[k])}`, cols[k]]))];
    })());

    const recent = card("Recently collected", "flagged names, newest first",
      table([
        { label: "Domain", cls: "dom", cell: (r) => domLink(r.name) },
        { label: "Verdict", cell: (r) => verdictChip(r.verdict) },
        { label: "Score", cell: (r) => scoreBar(r.score, r.verdict) },
        { label: "First cert", cell: (r) => h("span", { class: "mono nowrap" }, day(r.first_issued)) },
        { label: "DNS", cell: (r) => dnsChip(r.dns) },
      ], o.recent, { onRow: (r) => go("domain", { name: r.name }) }),
      h("div", { style: { "margin-top": "8px" } }, h("a", { href: "#/domains?sort=first_seen" }, "All flagged names →")));

    const brands = card("Brands impersonated", "likely + possible names per brand",
      o.brands.length ? hbars(o.brands, ["likely", "possible"], { likely: VCOL.likely, possible: VCOL.possible }, (r) => r.label, (r) => `#/domains?brand=${encodeURIComponent(r.brand)}&verdict=likely,possible`) : empty("No brand impersonation flagged."));
    const camps = card("Largest campaign hypotheses", "leads, not findings",
      o.top_campaigns.length ? table([
        { label: "Campaign", cell: (r) => campLink(r.id) },
        { label: "Tier", cell: (r) => tierChip(r.tier) },
        { label: "Names", num: true, cell: (r) => n(r.size) },
        { label: "Brands", cell: (r) => r.brands.map((b) => tag(b)) },
      ], o.top_campaigns, { onRow: (r) => go("campaign", { id: r.id }) }) : empty("No campaign hypotheses in this analysis."));

    return h("div", {},
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Overview"),
        h("p", {}, "Names impersonating Bulgarian brands, spotted in Certificate Transparency, scored by explainable rules and grouped into campaign hypotheses. Every number links to the records behind it."))),
      kpis,
      h("div", { class: "grid g-main" }, weekly, health),
      h("div", { class: "grid g-main", style: { "margin-top": "14px" } }, recent,
        h("div", { class: "grid" }, card("DNS state of flagged names", "latest check per name", dnsBar), brands, camps)));
  };
  PAGES[""].title = "Overview";
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
    const vbtn = (v) => h("button", { class: vset.has(v) ? "on" : null, "aria-pressed": vset.has(v) ? "true" : "false", onclick: () => {
      vset.has(v) ? vset.delete(v) : vset.add(v);
      upd({ verdict: [...vset].join(",") || "likely" });
    } }, v);
    let deb;
    const search = h("input", { class: "f", type: "search", value: st.q, placeholder: "filter by name…", maxlength: "100", "aria-label": "Filter by name",
      oninput: (e) => { clearTimeout(deb); deb = setTimeout(() => upd({ q: e.target.value.trim() }), 350); } });
    const sel = (name, opts, cur, label) => h("select", { "aria-label": label, onchange: (e) => upd({ [name]: e.target.value }) },
      opts.map(([val, lab]) => h("option", { value: val, selected: val === cur ? true : null }, lab)));
    const brands = Object.entries(META.brands).sort((a, b) => a[1].label.localeCompare(b[1].label));
    const sortBtn = (key, label) => h("button", { class: st.sort === key ? "on" : null, onclick: () => upd({ sort: key, order: st.sort === key && st.order === "desc" ? "asc" : "desc" }) },
      label, st.sort === key ? (st.order === "desc" ? " ↓" : " ↑") : "");
    const filters = h("div", { class: "filters" }, search,
      h("div", { class: "grp", role: "group", "aria-label": "Verdict" }, ["likely", "possible", "lead", "weak", "legitimate", "none"].map(vbtn)),
      sel("brand", [["", "all brands"], ...brands.map(([k, b]) => [k, b.label])], st.brand, "Brand"),
      sel("dns", [["", "any DNS state"], ["resolved", "resolving"], ["nxdomain", "NXDOMAIN"], ["no_address", "no address"], ["failed", "lookup failed"], ["unchecked", "not checked"]], st.dns, "DNS state"),
      sel("since_days", [["", "any time"], ["7", "last 7 days"], ["30", "last 30 days"], ["90", "last 90 days"], ["365", "last year"]], st.since_days, "Time window"),
      sel("since_field", [["first_seen", "…collected"], ["first_issued", "…first certificate"]], st.since_field, "Time field"),
      h("label", { class: "tog" }, h("input", { type: "checkbox", checked: st.campaign === "yes" ? true : null, onchange: (e) => upd({ campaign: e.target.checked ? "yes" : "" }) }), "in a campaign"));
    const cols = [
      { label: sortBtn("name", "Domain"), cls: "dom", cell: (r) => domLink(r.name) },
      { label: "Verdict", cell: (r) => verdictChip(r.verdict) },
      { label: sortBtn("score", "Score"), cell: (r) => scoreBar(r.score, r.verdict) },
      { label: "Brands", cell: (r) => r.brands.map((b) => tag(b)) },
      { label: sortBtn("first_issued", "First cert"), cell: (r) => h("span", { class: "mono nowrap" }, day(r.first_issued)) },
      { label: sortBtn("first_seen", "Collected"), cell: (r) => h("span", { class: "mono nowrap", title: r.first_seen_at }, day(r.first_seen_at)) },
      { label: "DNS", cell: (r) => h("span", { title: r.dns_at ? `checked ${dt(r.dns_at)} UTC` : "" }, dnsChip(r.dns)) },
      { label: "Campaign", cell: (r) => (r.campaign_id ? campLink(r.campaign_id) : h("span", { class: "faint" }, "–")) },
    ];
    const pager = h("div", { class: "pager" }, h("span", {}, `${n(data.total)} names · showing ${data.total ? st.offset + 1 : 0}–${Math.min(st.offset + data.limit, data.total)}`),
      h("span", {}, h("button", { class: "btn", disabled: st.offset === 0 ? true : null, onclick: () => go("domains", { ...st, offset: Math.max(0, st.offset - 100) }) }, "← Prev"), " ",
        h("button", { class: "btn", disabled: st.offset + data.limit >= data.total ? true : null, onclick: () => go("domains", { ...st, offset: st.offset + 100 }) }, "Next →")));
    return h("div", {},
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Domains"), h("p", {}, "Every name seen in a collected certificate, with the verdict of the current analysis. Filters are kept in the address, so a view can be shared."))),
      filters, h("section", { class: "card flush" }, table(cols, data.rows, { onRow: (r) => go("domain", { name: r.name }), empty: "No names match these filters." }), pager));
  };
  PAGES.domains.title = "Domains";

  // domain detail ----------------------------------------------------------------
  PAGES.domain = async function domain(params) {
    const d = await api("domain", { name: params.get("name") || "" });
    const dec = d.decision;
    const lastDns = d.dns[0];
    const pts = d.signals.filter((x) => x.points > 0);
    const totalPts = pts.reduce((a, x) => a + x.points, 0);
    const scoreStack = h("div", { class: "stack", role: "img", "aria-label": "score composition" }, pts.map((x, i) => {
      const sp = h("span", { style: { width: `${(x.points / Math.max(100, totalPts)) * 100}%`, background: x.corroborating ? "var(--likely)" : "var(--indigo)", opacity: 1 - i * 0.07, "animation-delay": `${i * 40}ms` } });
      tipOn(sp, () => h("div", {}, h("b", {}, `${x.rule} +${x.points}`), h("div", {}, x.detail)));
      return sp;
    }));
    const why = card("Why this verdict", dec ? `score ${dec.score} = capped sum of signals` : "",
      dec ? h("div", {}, h("div", { class: "explain" }, h("b", {}, `${dec.verdict}: `), META.verdicts[dec.verdict] || "",
        dec.verdict === "likely" || dec.verdict === "possible" ? " A brand token alone never qualifies; a corroborating signal (red) must accompany it." : ""),
      pts.length ? scoreStack : null,
      d.signals.length ? d.signals.map((x) => h("div", { class: "sigrow" },
        h("span", { class: "pts", style: { color: x.points ? (x.corroborating ? "var(--likely)" : "var(--indigo)") : "var(--faint)" } }, x.points ? `+${x.points}` : "0"),
        h("span", { class: "rule", title: x.text }, x.rule, x.corroborating ? h("span", { class: "faint", title: "corroborating signal" }, " ●") : null),
        h("span", { class: "det" }, h("b", {}, x.detail), h("br"), x.text))) : empty("No signals: nothing about this name matched a rule.")) : empty("Not scored in the current analysis."));

    const certs = card("Certificates", `${d.certificates.length} listing this name`,
      table([
        { label: "Issued", cell: (c) => h("a", { class: "mono nowrap", href: `#/certificate?id=${c.id}` }, day(c.not_before)) },
        { label: "Expires", cell: (c) => h("span", { class: "mono nowrap faint" }, day(c.not_after)) },
        { label: "Issuer", cell: (c) => h("span", { title: c.issuer_name }, (c.issuer_name || "").replace(/^.*CN=/, "")) },
        { label: "Names", num: true, cell: (c) => n(c.names) },
        { label: "Listed as", cell: (c) => [c.wildcard ? tag("*.wildcard") : null, (c.via || "").split(",").map((x) => tag(x === "common_name" ? "CN" : "SAN match"))] },
        { label: "crt.sh", cell: (c) => c.crtsh_ids.slice(0, 2).map((i) => h("div", {}, crtLink(i))) },
      ], d.certificates, { onRow: (c) => go("certificate", { id: c.id }) }));

    const accepted = d.relationships.filter((r) => r.accepted);
    const rejected = d.relationships.filter((r) => !r.accepted);
    const relTable = (rows) => table([
      { label: "Related name", cls: "dom", cell: (r) => domLink(r.a === d.domain.name ? r.b : r.a) },
      { label: "Strength", cell: (r) => tierChip(r.strength) },
      { label: "Weight", num: true, cell: (r) => h("span", { class: "mono" }, r.weight.toFixed(2)) },
      { label: "Evidence", cell: (r) => h("div", { class: "ev" }, r.evidence.map((e) => tag(`${e.kind}: ${e.value}`, `class ${e.class} · shared by ${e.df} flagged names · +${e.weight.toFixed(2)}`))) },
      { label: "Decision", cell: (r) => h("span", { class: "muted" }, r.reason) },
    ], rows, { rowClass: (r) => (r.accepted ? "relrow" : "relrow rej") });
    const rels = card("Related names", `${accepted.length} accepted relationship(s) · ${rejected.length} rejected candidate(s)`,
      accepted.length ? relTable(accepted) : empty("No accepted relationships."),
      rejected.length ? h("details", { style: { "margin-top": "10px" } }, h("summary", { class: "muted" }, `Show ${rejected.length} candidate relationship(s) that did not meet the corroboration rules`), relTable(rejected)) : null);

    const status = card("Status", null, kv([
      ["Registrable", h("span", { class: "mono" }, d.domain.registrable)],
      ["Collected first", h("span", {}, h("span", { class: "mono" }, dt(d.domain.first_seen_at)), " UTC ", h("span", { class: "faint" }, `(${ago(d.domain.first_seen_at)})`))],
      ["First certificate", h("span", { class: "mono" }, day(dec?.first_issued))],
      ["DNS now", lastDns ? h("span", {}, dnsChip(lastDns.outcome), h("span", { class: "faint" }, ` checked ${dt(lastDns.checked_at)} UTC`)) : dnsChip(null)],
      lastDns?.addresses?.length ? ["Addresses", h("span", { class: "mono" }, lastDns.addresses.join(", "))] : null,
      ["Campaign", d.campaign ? h("span", {}, campLink(d.campaign.id), " ", tierChip(d.campaign.tier), h("span", { class: "faint" }, ` ${d.campaign.size} names`)) : h("span", { class: "faint" }, "none")],
    ]));
    const dnsHist = card("DNS history", `${d.dns.length} observation(s) · appended, never overwritten`,
      d.dns.length ? table([
        { label: "Checked (UTC)", cell: (o) => h("span", { class: "mono nowrap" }, dt(o.checked_at)) },
        { label: "Outcome", cell: (o) => dnsChip(o.outcome) },
        { label: "Addresses", cell: (o) => h("span", { class: "mono break" }, o.addresses.join(", ") || "–") },
        { label: "Run", cell: (o) => h("a", { href: `#/run?id=${o.run_id}` }, `#${o.run_id}`) },
      ], d.dns) : empty("Not DNS-checked yet (only flagged names are checked)."));
    const inds = card("Correlation indicators", "what this name carries into correlation",
      d.indicators.length ? table([
        { label: "Kind", cell: (i) => h("span", { class: "mono" }, i.kind) },
        { label: "Value", cell: (i) => h("span", { class: "mono break" }, i.value) },
        { label: "Class", cell: (i) => i.class },
        { label: "df", num: true, title: "flagged names sharing this value", cell: (i) => n(i.df) },
        { label: "Weight", num: true, cell: (i) => h("span", { class: i.status === "active" ? "mono" : "mono faint", title: i.status }, i.status === "active" ? i.weight.toFixed(2) : i.status.replace("_", " ")) },
      ], d.indicators) : empty("Only flagged names are correlated."));
    const prov = card("Source provenance", "the exact records this name came from",
      table([
        { label: "Record", cell: (r) => h("span", { class: "mono" }, `#${r.id}`) },
        { label: "crt.sh", cell: (r) => crtLink(r.crtsh_id) },
        { label: "Query", cell: (r) => h("span", { class: "mono" }, r.query) },
        { label: "Run", cell: (r) => h("a", { href: `#/run?id=${r.run_id}` }, `#${r.run_id}`) },
        { label: "Fetched (UTC)", cell: (r) => h("span", { class: "mono nowrap" }, dt(r.fetched_at)) },
        { label: "Payload SHA-256", cell: (r) => h("span", { class: "mono", title: r.payload_sha256 }, short(r.payload_sha256, 16)) },
      ], d.records),
      h("p", { class: "faint", style: { "margin-top": "8px" } }, `Scored by rules ${d.provenance.rules_version} in analysis #${d.provenance.analysis_id} (as of ${dt(d.provenance.as_of)} UTC, dataset ${short(d.provenance.dataset_sha256, 16)}).`));

    return h("div", {},
      h("div", { class: "hero" }, h("h1", {}, d.domain.name), dec ? verdictChip(dec.verdict) : null,
        dec ? h("span", { class: "score", style: { color: VCOL[dec.verdict] } }, dec.score) : null,
        dec ? dec.brands.map((b) => tag(META.brands[b]?.label || b)) : null),
      h("div", { class: "grid g-main" }, h("div", { class: "grid" }, why, rels, certs), h("div", { class: "grid" }, status, dnsHist, inds)),
      h("div", { style: { "margin-top": "14px" } }, prov));
  };
  PAGES.domain.title = "Domain";
  PAGES.domain.crumbs = (p) => [h("a", { href: "#/domains" }, "Domains"), p.get("name") || ""];

  // certificates ---------------------------------------------------------------
  PAGES.certificates = async function certificates(params) {
    const st = { q: params.get("q") || "", flagged: params.get("flagged") || "yes", offset: Number(params.get("offset") || 0) };
    const data = await api("certificates", { ...st, limit: 100 });
    let deb;
    const upd = (patch) => go("certificates", { ...st, offset: 0, ...patch });
    const filters = h("div", { class: "filters" },
      h("input", { class: "f", type: "search", value: st.q, placeholder: "name, issuer or serial…", maxlength: "100", "aria-label": "Search certificates",
        oninput: (e) => { clearTimeout(deb); deb = setTimeout(() => upd({ q: e.target.value.trim() }), 350); } }),
      h("div", { class: "grp" }, [["yes", "with flagged names"], ["all", "all certificates"]].map(([k, l]) => h("button", { class: st.flagged === k ? "on" : null, onclick: () => upd({ flagged: k }) }, l))));
    const pager = h("div", { class: "pager" }, h("span", {}, `${n(data.total)} certificates`),
      h("span", {}, h("button", { class: "btn", disabled: st.offset === 0 ? true : null, onclick: () => go("certificates", { ...st, offset: Math.max(0, st.offset - 100) }) }, "← Prev"), " ",
        h("button", { class: "btn", disabled: st.offset + 100 >= data.total ? true : null, onclick: () => go("certificates", { ...st, offset: st.offset + 100 }) }, "Next →")));
    return h("div", {},
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Certificates"), h("p", {}, "Precertificate and final certificate share issuer and serial, so they appear once here with both crt.sh records. crt.sh lists only the identities that matched our keywords, so 'names' is what we saw, not necessarily every name on the certificate."))),
      filters,
      h("section", { class: "card flush" }, table([
        { label: "Issued", cell: (c) => h("a", { class: "mono nowrap", href: `#/certificate?id=${c.id}` }, day(c.not_before)) },
        { label: "Issuer", cell: (c) => h("span", { title: c.issuer_name }, (c.issuer_name || "").replace(/^.*CN=/, "")) },
        { label: "Serial", cell: (c) => h("span", { class: "mono", title: c.serial }, short(c.serial, 14)) },
        { label: "Names seen", num: true, cell: (c) => n(c.names) },
        { label: "Flagged names", cls: "dom", cell: (c) => c.flagged_names.slice(0, 3).map((x) => h("div", {}, domLink(x))) },
        { label: "Max score", num: true, cell: (c) => (c.max_score === null ? "–" : h("span", { class: "mono" }, c.max_score)) },
        { label: "Collected", cell: (c) => h("span", { class: "mono nowrap faint" }, day(c.first_seen_at)) },
      ], data.rows, { onRow: (c) => go("certificate", { id: c.id }) }), pager));
  };
  PAGES.certificates.title = "Certificates";

  PAGES.certificate = async function certificate(params) {
    const d = await api("certificate", { id: params.get("id") || "" });
    const c = d.certificate;
    return h("div", {},
      h("div", { class: "hero" }, h("h1", {}, `Certificate ${short(c.serial, 20)}`), tag((c.issuer_name || "").replace(/^.*CN=/, ""))),
      h("div", { class: "grid g-main" },
        h("div", { class: "grid" },
          card("Names on this certificate", "as returned by crt.sh for our queries",
            table([
              { label: "Name", cls: "dom", cell: (r) => domLink(r.name) },
              { label: "Listed as", cell: (r) => [r.wildcard ? tag("*.wildcard") : null, tag(r.via === "common_name" ? "CN" : "SAN match")] },
              { label: "Verdict", cell: (r) => (r.verdict ? verdictChip(r.verdict) : "–") },
              { label: "Score", cell: (r) => (r.score === null ? "–" : scoreBar(r.score, r.verdict)) },
            ], d.names)),
          card("Source records", "verbatim crt.sh JSON, as stored",
            d.records.map((r) => h("div", { style: { "margin-bottom": "12px" } },
              h("div", { class: "muted", style: { "margin-bottom": "4px" } }, `record #${r.id} · `, crtLink(r.crtsh_id), ` · query `, h("span", { class: "mono" }, r.query), ` · run `, h("a", { href: `#/run?id=${r.run_id}` }, `#${r.run_id}`), ` · sha256 ${short(r.payload_sha256, 16)}`),
              h("pre", { class: "mono", style: { margin: 0, padding: "10px", background: "var(--bg-2)", border: "1px solid var(--line)", "border-radius": "6px", overflow: "auto", "white-space": "pre-wrap", "word-break": "break-all" } }, JSON.stringify(r.payload, null, 2)))))),
        card("Certificate", null, kv([
          ["Issuer", h("span", { class: "break" }, c.issuer_name)],
          ["Serial", h("span", { class: "mono break" }, c.serial)],
          ["Key", h("span", { class: "mono break" }, c.cert_key)],
          ["Common name", h("span", { class: "mono break" }, c.common_name || "–")],
          ["Not before", h("span", { class: "mono" }, dt(c.not_before))],
          ["Not after", h("span", { class: "mono" }, dt(c.not_after))],
          ["First collected", h("span", { class: "mono" }, `${dt(c.first_seen_at)} UTC`)],
        ]))));
  };
  PAGES.certificate.title = "Certificate";
  PAGES.certificate.crumbs = (p) => [h("a", { href: "#/certificates" }, "Certificates"), `#${p.get("id")}`];

  // campaigns ----------------------------------------------------------------------
  const TIER_TEXT = {
    strong: "Every member is connected through strong indicators alone (same registrable domain or same certificate).",
    corroborated: "Members are linked by relationships corroborated by several independent indicator kinds.",
    chained: "A sparse group: members are connected through intermediaries more than to each other. Review before relying on it.",
  };
  PAGES.campaigns = async function campaigns(params) {
    const tier = params.get("tier") || "";
    const d = await api("campaigns", { tier });
    return h("div", {},
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Campaign hypotheses"),
        h("p", {}, "Groups of flagged names connected by accepted relationships. A campaign is a hypothesis about shared infrastructure - a lead for an investigator, not proof of common ownership, and never attribution to a person."))),
      h("div", { class: "filters" }, h("div", { class: "grp" }, [["", "all tiers"], ["strong", "strong"], ["corroborated", "corroborated"], ["chained", "chained"]].map(([k, l]) =>
        h("button", { class: tier === k ? "on" : null, title: TIER_TEXT[k] || "", onclick: () => go("campaigns", { tier: k }) }, l)))),
      h("section", { class: "card flush" }, table([
        { label: "Campaign", cell: (r) => campLink(r.id) },
        { label: "Tier", cell: (r) => h("span", { title: TIER_TEXT[r.tier] }, tierChip(r.tier)) },
        { label: "Names", num: true, cell: (r) => n(r.size) },
        { label: "Links", num: true, cell: (r) => n(r.edges) },
        { label: "Density", num: true, title: "accepted links / possible links", cell: (r) => h("span", { class: "mono" }, r.density.toFixed(2)) },
        { label: "Cohesion", num: true, title: "mean link weight", cell: (r) => h("span", { class: "mono" }, r.cohesion.toFixed(2)) },
        { label: "Brands", cell: (r) => r.brands.map((b) => tag(b)) },
        { label: "Issued", cell: (r) => h("span", { class: "mono nowrap" }, `${day(r.first_issued)} → ${day(r.last_issued)}`) },
        { label: "Members", cls: "dom", cell: (r) => h("span", { class: "muted" }, r.members.slice(0, 3).join(", "), r.members.length > 3 ? ` +${r.members.length - 3}` : "") },
      ], d.rows, { onRow: (r) => go("campaign", { id: r.id }), empty: "No campaign hypotheses in this analysis." })),
      h("p", { class: "faint", style: { "margin-top": "10px" } }, `Correlation settings: min_edge ${d.config.min_edge}, min_kinds ${d.config.min_kinds}, require a non-weak kind: ${d.config.require_non_weak}. See Methodology.`));
  };
  PAGES.campaigns.title = "Campaigns";

  PAGES.campaign = async function campaign(params) {
    const d = await api("campaign", { id: params.get("id") || "" });
    const c = d.campaign;
    const evBox = h("div", { class: "evbox" }, h("p", { class: "muted" }, "Select a link or a name in the graph to see the evidence behind it."));
    const showEdge = (e) => {
      evBox.replaceChildren(h("h3", { style: { "margin-bottom": "6px" } }, domLink(e.a), " ↔ ", domLink(e.b)),
        h("p", {}, tierChip(e.strength), ` weight ${e.weight.toFixed(2)} · ${e.reason}`),
        table([
          { label: "Indicator", cell: (x) => h("span", { class: "mono" }, x.kind) },
          { label: "Shared value", cell: (x) => h("span", { class: "mono break" }, x.value) },
          { label: "Class", cell: (x) => x.class },
          { label: "Shared by", num: true, title: "flagged names carrying this value", cell: (x) => n(x.df) },
          { label: "Weight", num: true, cell: (x) => h("span", { class: "mono" }, `+${x.weight.toFixed(2)}`) },
        ], e.evidence));
    };
    const showNode = (m) => {
      const mine = d.edges.filter((e) => e.a === m.name || e.b === m.name);
      evBox.replaceChildren(h("h3", { style: { "margin-bottom": "6px" } }, domLink(m.name)),
        h("p", {}, verdictChip(m.verdict), ` score ${m.score} · first certificate ${day(m.first_issued)} · `, dnsChip(m.dns)),
        h("p", { class: "muted" }, `${mine.length} accepted link(s) inside this campaign. Click a link for its evidence.`));
    };
    const graph = forceGraph(d.members, d.edges, showEdge, showNode);
    const tl = memberTimeline(d.members);
    return h("div", {},
      h("div", { class: "hero" }, h("h1", {}, c.id), tierChip(c.tier),
        h("span", { class: "muted" }, `${c.size} names · ${c.edges} links · density ${c.density.toFixed(2)} · cohesion ${c.cohesion.toFixed(2)} · weakest link ${c.min_weight.toFixed(2)}`)),
      h("div", { class: `explain ${c.tier === "chained" ? "warn" : ""}` }, h("b", {}, `${c.tier}: `), TIER_TEXT[c.tier],
        " This group is a hypothesis about shared infrastructure, derived from the evidence below; it is not proof of common ownership."),
      h("div", { class: "grid g-main" },
        h("div", { class: "grid" }, card("Relationship graph", "node colour = verdict · line = strength · thickness = weight", graph), card("Evidence", null, evBox), card("Issuance timeline", "first certificate of each member", tl)),
        h("div", { class: "grid" },
          card("Members", null, table([
            { label: "Name", cls: "dom", cell: (m) => domLink(m.name) },
            { label: "Verdict", cell: (m) => verdictChip(m.verdict) },
            { label: "Score", num: true, cell: (m) => h("span", { class: "mono" }, m.score) },
            { label: "First cert", cell: (m) => h("span", { class: "mono nowrap" }, day(m.first_issued)) },
            { label: "DNS", cell: (m) => dnsChip(m.dns) },
          ], d.members)),
          card("Shared indicators", "values carried by 2+ members", table([
            { label: "Kind", cell: (x) => h("span", { class: "mono" }, x.kind) },
            { label: "Value", cell: (x) => h("span", { class: "mono break" }, x.value) },
            { label: "Members", num: true, cell: (x) => n(x.members) },
            { label: "Corpus df", num: true, title: "flagged names in the whole analysis carrying it", cell: (x) => n(x.df) },
            { label: "Weight", num: true, cell: (x) => h("span", { class: x.status === "active" ? "mono" : "mono faint", title: x.status }, x.status === "active" ? x.weight.toFixed(2) : x.status.replace("_", " ")) },
          ], d.shared_indicators)))));
  };
  PAGES.campaign.title = "Campaign";
  PAGES.campaign.crumbs = (p) => [h("a", { href: "#/campaigns" }, "Campaigns"), p.get("id") || ""];

  function forceGraph(members, edges, onEdge, onNode) {
    const N = members.length;
    const idx = new Map(members.map((m, i) => [m.name, i]));
    const pos = members.map((m, i) => ({ x: Math.cos((2 * Math.PI * i) / N) * 150, y: Math.sin((2 * Math.PI * i) / N) * 150, vx: 0, vy: 0 }));
    const E = edges.map((e) => ({ ...e, s: idx.get(e.a), t: idx.get(e.b) })).filter((e) => e.s !== undefined && e.t !== undefined);
    const ideal = N > 40 ? 60 : 150;
    for (let it = 0; it < 320; it++) {
      const alpha = 1 - it / 320;
      for (let i = 0; i < N; i++) for (let j = i + 1; j < N; j++) {
        const dx = pos[j].x - pos[i].x, dy = pos[j].y - pos[i].y;
        const d2 = Math.max(25, dx * dx + dy * dy), f = (1800 * alpha) / d2, d = Math.sqrt(d2);
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
    // Never zoom in past 1:1 - the view box is at least the size of the 460px-tall
    // panel, so labels keep their real size on small campaigns.
    const cx = (Math.min(...xs) + Math.max(...xs)) / 2, cy = (Math.min(...ys) + Math.max(...ys)) / 2;
    const w = Math.max(Math.max(...xs) - Math.min(...xs) + 2 * pad + 260, 560);
    const hh = Math.max(Math.max(...ys) - Math.min(...ys) + 2 * pad, 380);
    let vb = { x: cx - w / 2, y: cy - hh / 2, w, h: hh };
    const svg = s("svg", { viewBox: `${vb.x} ${vb.y} ${vb.w} ${vb.h}`, role: "img", "aria-label": `Relationship graph of ${N} names` });
    const setVB = () => svg.setAttribute("viewBox", `${vb.x} ${vb.y} ${vb.w} ${vb.h}`);
    const edgeEls = E.map((e) => {
      const col = e.strength === "strong" ? "var(--strong)" : "var(--corr)";
      const ln = s("line", { class: "edge", x1: pos[e.s].x, y1: pos[e.s].y, x2: pos[e.t].x, y2: pos[e.t].y, stroke: col, "stroke-width": 1 + Math.min(4, e.weight / 3), "stroke-opacity": 0.75 });
      ln.addEventListener("click", (ev) => { ev.stopPropagation(); select(ln); onEdge(e); });
      tipOn(ln, () => h("div", {}, h("b", {}, `${e.strength} · ${e.weight.toFixed(2)}`), h("div", {}, e.kinds.join(" + "))));
      return ln;
    });
    let selected = null;
    const select = (el) => { if (selected) selected.classList.remove("sel"); selected = el; el.classList.add("sel"); };
    const nodeEls = members.map((m, i) => {
      const r = 5 + (m.score / 100) * 6;
      const g = s("g", { class: "node", transform: `translate(${pos[i].x},${pos[i].y})`, tabindex: "0", role: "button", "aria-label": m.name },
        s("circle", { r, fill: VCOL[m.verdict] || "var(--weak)" }),
        N <= 40 ? s("text", pos[i].x < cx ? { x: -(r + 5), y: 3.5, "text-anchor": "end" } : { x: r + 5, y: 3.5 },
          m.name.length > 34 ? `${m.name.slice(0, 32)}…` : m.name) : null);
      const act = () => { select(g.firstChild); onNode(m); for (const [k, ln] of edgeEls.entries()) ln.setAttribute("stroke-opacity", E[k].a === m.name || E[k].b === m.name ? 1 : 0.15); };
      g.addEventListener("click", (ev) => { ev.stopPropagation(); act(); });
      g.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); act(); } });
      g.addEventListener("dblclick", () => go("domain", { name: m.name }));
      tipOn(g, () => h("div", {}, h("b", {}, m.name), h("div", {}, `${m.verdict} · score ${m.score}`), h("div", { class: "muted" }, "double-click to open")));
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
      h("div", { class: "graph-legend" }, h("span", {}, h("i", { style: { "border-color": "var(--strong)" } }), "strong"), h("span", {}, h("i", { style: { "border-color": "var(--corr)" } }), "corroborated"), h("span", { class: "faint" }, "scroll to zoom · drag to pan")));
  }

  function memberTimeline(members) {
    const pts = members.filter((m) => m.first_issued).map((m) => ({ ...m, t: Date.parse(m.first_issued.slice(0, 10)) }));
    if (!pts.length) return empty("No issuance dates.");
    const W = 760, H = 70, pad = 30;
    const t0 = Math.min(...pts.map((p) => p.t)), t1 = Math.max(...pts.map((p) => p.t));
    const span = Math.max(864e5, t1 - t0);
    const x = (t) => pad + ((t - t0) / span) * (W - 2 * pad);
    const svg = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}` },
      s("line", { class: "grid-l", x1: pad, x2: W - pad, y1: 34, y2: 34 }),
      s("text", { x: pad, y: 62, "text-anchor": "start" }, new Date(t0).toISOString().slice(0, 10)),
      s("text", { x: W - pad, y: 62, "text-anchor": "end" }, new Date(t1).toISOString().slice(0, 10)));
    const stackAt = new Map();
    for (const p of pts) {
      const key = Math.round(x(p.t) / 6);
      const k = stackAt.get(key) || 0; stackAt.set(key, k + 1);
      const c = s("circle", { cx: x(p.t), cy: 34 - k * 7, r: 3.5, fill: VCOL[p.verdict] || "var(--weak)", style: { cursor: "pointer" } });
      c.addEventListener("click", () => go("domain", { name: p.name }));
      tipOn(c, () => h("div", {}, h("b", {}, p.name), h("div", {}, `first certificate ${day(p.first_issued)}`)));
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
    const labels = { issued: "certificate issued", first_seen: "first collected", dns_change: "DNS state changed" };
    const byDay = new Map();
    for (const e of d.events) { const k = e.t.slice(0, 10); if (!byDay.has(k)) byDay.set(k, []); byDay.get(k).push(e); }
    const list = [...byDay.entries()].map(([k, evs]) => h("div", {}, h("div", { class: "timeline-day" }, `${k} · ${evs.length} event(s)`),
      evs.map((e) => h("div", { class: "tl-ev" }, h("span", { class: "tm" }, e.t.slice(11, 16) || "–"),
        h("span", { style: { color: cols[e.type] } }, h("span", { class: "dot" }), labels[e.type]),
        h("span", { class: "mono break" }, domLink(e.domain), " ", h("span", { class: "muted" }, e.detail || "")),
        verdictChip(e.verdict)))));
    return h("div", {},
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Timeline"), h("p", {}, "Chronology of flagged names: when certificates were issued, when this system first collected them, and when their DNS state changed."))),
      h("div", { class: "filters" },
        h("div", { class: "grp" }, [["7", "7 days"], ["30", "30 days"], ["90", "90 days"], ["365", "1 year"]].map(([k, l]) => h("button", { class: days === k ? "on" : null, onclick: () => go("timeline", { days: k, kind }) }, l))),
        h("div", { class: "grp" }, [["all", "all events"], ["issued", "issued"], ["first_seen", "collected"], ["dns_change", "DNS changes"]].map(([k, l]) => h("button", { class: kind === k ? "on" : null, onclick: () => go("timeline", { days, kind: k }) }, l)))),
      card("Events per day", `${n(d.total)} event(s) in ${d.days} days`,
        stackedBars({ data: d.daily, keys: ["issued", "first_seen", "dns_change"], colors: cols, height: 130,
          label: (x, i) => (i % Math.max(1, Math.round(d.daily.length / 8)) === 0 ? x.day.slice(5) : ""),
          tipFor: (x) => h("div", {}, h("b", {}, x.day), h("div", {}, `issued ${x.issued} · collected ${x.first_seen} · DNS ${x.dns_change}`)) }),
        legend(Object.entries(labels).map(([k, l]) => [l, cols[k]]))),
      h("div", { style: { "margin-top": "14px" } }, card("Events", d.total > d.events.length ? `newest ${d.events.length} of ${n(d.total)}` : null, d.events.length ? list : empty("No events in this window."))));
  };
  PAGES.timeline.title = "Timeline";

  // sources ------------------------------------------------------------------------
  PAGES.sources = async function sources() {
    const d = await api("sources");
    return h("div", {},
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Sources"), h("p", {}, "Every public source the system reads, what it provides, and how reliably it answered. No third-party phishing feed is used; every record comes from this system's own collection."))),
      h("div", { class: "grid g2" }, d.sources.map((x) => card(x.name, x.kind,
        h("p", {}, x.description), h("p", { class: "muted" }, x.provenance),
        kv([
          ["Endpoint", h("span", { class: "mono break" }, x.endpoint)],
          ["Runs", h("span", {}, n(x.runs), " ", Object.entries(x.status_counts).map(([k, v]) => h("span", { style: { "margin-left": "8px" } }, statusChip(k), ` ${v}`)))],
          ["Answer rate · 7 d", h("span", {}, pct(x.answer_rate_7d), h("span", { class: "faint" }, " of requested queries/lookups got a definitive answer"))],
          ["Last complete run", h("span", { class: "mono" }, x.last_complete ? `${dt(x.last_complete)} UTC` : "never")],
          ["Last run", x.last_run ? h("span", {}, statusChip(x.last_run.status), " ", h("a", { href: `#/run?id=${x.last_run.id}` }, `#${x.last_run.id}`), ` ${dt(x.last_run.started_at)} UTC`) : "–"],
          ["Records stored", n(x.records)],
        ])))),
      h("div", { style: { "margin-top": "14px" } }, card("Network dependencies", "every external connection, and who makes it", table([
        { label: "From", cell: (r) => h("b", {}, r.from) },
        { label: "To", cell: (r) => h("span", { class: "mono break" }, r.to) },
        { label: "Purpose", cell: (r) => r.purpose },
        { label: "When", cell: (r) => r.when },
        { label: "Note", cell: (r) => h("span", { class: "muted" }, r.note) },
      ], d.network))));
  };
  PAGES.sources.title = "Sources";

  // collection -----------------------------------------------------------------------
  PAGES.collection = async function collection(params) {
    const src = params.get("source") || "";
    const offset = Number(params.get("offset") || 0);
    const [runs, an] = await Promise.all([api("runs", { source: src, limit: 50, offset }), api("analyses")]);
    const crt = runs.rows.filter((r) => r.source_id === "crtsh");
    return h("div", {},
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "Collection"), h("p", {}, "Partial collection is normal against a free shared service, so it is recorded, never hidden: a failed or abandoned query is never counted as 'no results'."))),
      crt.length ? card("crt.sh query outcomes", "per run, newest right · click a bar for the run", runStrip(crt.slice(0, 40))) : null,
      h("div", { class: "filters", style: { "margin-top": "14px" } }, h("div", { class: "grp" }, [["", "all sources"], ["crtsh", "crt.sh"], ["dns", "DNS"]].map(([k, l]) => h("button", { class: src === k ? "on" : null, onclick: () => go("collection", { source: k }) }, l)))),
      h("section", { class: "card flush" }, table([
        { label: "Run", cell: (r) => h("a", { href: `#/run?id=${r.id}` }, `#${r.id}`) },
        { label: "Source", cell: (r) => r.source_id },
        { label: "Started (UTC)", cell: (r) => h("span", { class: "mono nowrap" }, dt(r.started_at)) },
        { label: "Duration", num: true, cell: (r) => secs(r.duration_s) },
        { label: "Status", cell: (r) => statusChip(r.status) },
        { label: "Requested", num: true, cell: (r) => n(r.queries_requested) },
        { label: "Answered", num: true, cell: (r) => n(r.queries_ok) },
        { label: "Empty", num: true, cell: (r) => n(r.queries_empty) },
        { label: "Abandoned", num: true, cell: (r) => n(r.queries_abandoned) },
        { label: "Timeout", num: true, cell: (r) => n(r.queries_timeout) },
        { label: "Failed", num: true, cell: (r) => n(r.queries_failed) },
        { label: "Skipped", num: true, cell: (r) => n(r.queries_skipped) },
        { label: "Records (new)", num: true, cell: (r) => `${n(r.records_received)} (${n(r.records_new)})` },
        { label: "Software", cell: (r) => h("span", { class: "mono faint" }, r.software_version) },
      ], runs.rows, { onRow: (r) => go("run", { id: r.id }) }),
        h("div", { class: "pager" }, h("span", {}, `${n(runs.total)} runs`), h("span", {},
          h("button", { class: "btn", disabled: offset === 0 ? true : null, onclick: () => go("collection", { source: src, offset: Math.max(0, offset - 50) }) }, "← Newer"), " ",
          h("button", { class: "btn", disabled: offset + 50 >= runs.total ? true : null, onclick: () => go("collection", { source: src, offset: offset + 50 }) }, "Older →")))),
      h("div", { class: "grid g2", style: { "margin-top": "14px" } },
        card("Analyses", "each one records its exact inputs and outputs", table([
          { label: "#", cell: (a) => a.id },
          { label: "As of (UTC)", cell: (a) => h("span", { class: "mono nowrap" }, dt(a.as_of)) },
          { label: "Rules", cell: (a) => h("span", { class: "mono" }, a.rules_version) },
          { label: "Dataset", cell: (a) => h("span", { class: "mono", title: a.dataset_sha256 }, short(a.dataset_sha256)) },
          { label: "Results", cell: (a) => h("span", { class: "mono", title: a.results_sha256 }, short(a.results_sha256)) },
          { label: "Flagged", num: true, cell: (a) => n(a.domains_flagged) },
          { label: "Campaigns", num: true, cell: (a) => n(a.campaigns_total) },
        ], an.analyses)),
        card("Snapshots", "portable, fingerprinted exports", table([
          { label: "Created (UTC)", cell: (x) => h("span", { class: "mono nowrap" }, dt(x.created_at)) },
          { label: "Analysis", cell: (x) => `#${x.analysis_id}` },
          { label: "Dataset SHA-256", cell: (x) => h("span", { class: "mono", title: x.dataset_sha256 }, short(x.dataset_sha256, 16)) },
          { label: "File", cell: (x) => h("span", { class: "mono break" }, x.file_name) },
          { label: "Size", num: true, cell: (x) => bytes(x.bytes) },
        ], an.snapshots, { empty: "No snapshot exported yet." }))));
  };
  PAGES.collection.title = "Collection";

  PAGES.run = async function run(params) {
    const d = await api("run", { id: params.get("id") || "" });
    const r = d.run;
    const cov = r.note?.coverage;
    const isCrt = r.source_id === "crtsh";
    return h("div", {},
      h("div", { class: "hero" }, h("h1", {}, `Run #${r.id}`), statusChip(r.status), h("span", { class: "muted" }, `${r.source_id} · ${dt(r.started_at)} UTC · ${secs(r.duration_s)} · trawl ${r.software_version}`)),
      h("div", { class: "grid g-main" },
        isCrt ? card("Queries", `${d.queries.length} requests to crt.sh`, table([
          { label: "Keyword", cell: (q) => h("span", { class: "mono" }, q.keyword) },
          { label: "Role", cell: (q) => q.role },
          { label: "Pattern", cell: (q) => h("span", { class: "mono" }, q.query) },
          { label: "Outcome", cell: (q) => h("span", { style: { color: OUTCOME_COL[q.outcome] }, title: q.error || "" }, h("span", { class: "dot" }), q.outcome) },
          { label: "HTTP", num: true, cell: (q) => q.http_status ?? "–" },
          { label: "Tries", num: true, cell: (q) => q.attempts },
          { label: "Time", num: true, cell: (q) => secs(q.duration_s) },
          { label: "Bytes", num: true, cell: (q) => bytes(q.bytes) },
          { label: "Records (new)", num: true, cell: (q) => (q.records === null ? "–" : `${n(q.records)} (${n(q.records_new)})`) },
          { label: "Note", cell: (q) => h("span", { class: "muted" }, q.error || "") },
        ], d.queries)) : card("DNS results", `${d.dns.length} lookups`, table([
          { label: "Name", cls: "dom", cell: (o) => domLink(o.domain) },
          { label: "Outcome", cell: (o) => dnsChip(o.outcome) },
          { label: "Addresses", cell: (o) => h("span", { class: "mono break" }, o.addresses.join(", ") || "–") },
          { label: "Error", cell: (o) => h("span", { class: "muted" }, o.error || "") },
        ], d.dns)),
        h("div", { class: "grid" },
          card("Summary", null, kv([
            ["Requested", n(r.queries_requested)], ["Answered (records)", n(r.queries_ok)], ["Answered (empty)", n(r.queries_empty)],
            isCrt ? ["Abandoned by crt.sh", n(r.queries_abandoned)] : null, ["Timeouts", n(r.queries_timeout)], ["Failed", n(r.queries_failed)],
            isCrt ? ["Skipped (time budget)", n(r.queries_skipped)] : null, ["Records received", n(r.records_received)], ["New records", n(r.records_new)],
            ["Finished", h("span", { class: "mono" }, r.finished_at ? `${dt(r.finished_at)} UTC` : "–")],
          ])),
          cov ? card("Keyword coverage", "full = the contains-pattern answered", h("div", {}, Object.entries(cov).sort().map(([k, c]) => h("div", { class: "hbar" }, h("span", { class: "mono" }, k), h("span", { class: "track" }, h("span", { style: { width: c === "full" ? "100%" : c === "partial" ? "50%" : "4%", background: c === "full" ? "var(--live)" : c === "partial" ? "var(--possible)" : "var(--likely)" } })), h("span", { class: "muted" }, c))))) : null,
          card("Configuration", "as recorded at run time", h("pre", { class: "mono", style: { margin: 0, "white-space": "pre-wrap", "word-break": "break-all", color: "var(--text-2)" } }, JSON.stringify(r.config_json, null, 2))))));
  };
  PAGES.run.title = "Run";
  PAGES.run.crumbs = (p) => [h("a", { href: "#/collection" }, "Collection"), `Run #${p.get("id")}`];

  // methodology -------------------------------------------------------------------------
  PAGES.methodology = async function methodology() {
    const m = await api("methodology");
    const p = m.provenance;
    const corr = m.correlation;
    const list = (arr) => h("div", { class: "ev" }, arr.map((x) => tag(x)));
    return h("div", { class: "prose" },
      h("div", { class: "page-head" }, h("div", {}, h("h1", {}, "About & methodology"), h("p", {}, "What this system does, what it cannot establish, and the exact rules and settings behind everything on screen. The tables below are served by the running code, not written by hand."))),
      h("div", { class: "explain warn" }, h("b", {}, "Independent portfolio / research demonstration. "), "Not affiliated with or endorsed by ГДБОП or any other authority, and not affiliated with the author of any third-party phishing feed. Nothing here identifies a person. Outputs are leads for investigation, not findings."),
      h("h3", {}, "What it does"),
      h("ol", {},
        h("li", {}, "Collects certificate records from crt.sh, a public index of Certificate Transparency logs, by querying keywords for tracked Bulgarian brands. Every response is stored verbatim with its query, run and hash."),
        h("li", {}, "Scores every name with explainable rules. A score is the capped sum of named signals; each signal says what it matched."),
        h("li", {}, "Re-checks flagged names in DNS (lookup only) and appends each result, so appearance and disappearance are both kept."),
        h("li", {}, "Correlates flagged names into campaign hypotheses from shared indicators, weighted by rarity and requiring corroboration."),
        h("li", {}, "Records provenance for every analysis: input cut-offs, dataset SHA-256, rules version, correlation settings and a results SHA-256 that a replay from a snapshot must reproduce.")),
      h("h3", {}, "What it cannot establish"),
      h("ul", {},
        h("li", {}, "That a site is malicious. It never visits sites. A certificate for a look-alike name is a signal, not proof."),
        h("li", {}, "Who operates anything. Shared infrastructure is a hypothesis about common control, never attribution."),
        h("li", {}, "Completeness. Phishing on plain HTTP, on compromised legitimate sites, or behind wildcard certificates is invisible to certificate search; crt.sh itself abandons some queries (recorded per run)."),
        h("li", {}, "Accuracy on real data. The rules are tested against known examples and synthetic campaigns; no labelled ground truth for Bulgarian phishing exists.")),
      h("h3", {}, "Terms"),
      table([{ label: "Term", cell: (g) => h("b", {}, g[0]) }, { label: "Meaning", cell: (g) => g[1] }], m.glossary),
      h("h3", {}, `Scoring rules · ${m.rules_version}`),
      table([
        { label: "Rule", cell: (r) => h("span", { class: "mono" }, r.id) },
        { label: "Points", num: true, cell: (r) => h("span", { class: "mono" }, r.points) },
        { label: "Corroborating", cell: (r) => (r.corroborating ? "yes" : "–") },
        { label: "Meaning", cell: (r) => r.text },
      ], m.rules),
      h("p", { class: "muted", style: { "margin-top": "8px" } }, `Thresholds: likely ≥ ${m.thresholds.likely}, possible ≥ ${m.thresholds.possible}, both requiring a brand and at least one corroborating signal. Recent issuance window: ${m.recent_days} days before the analysis time. Words match only as whole tokens or as complete segmentations of a glued token - never as substrings.`),
      table([{ label: "Verdict", cell: (v) => verdictChip(v.id) }, { label: "Meaning", cell: (v) => v.text }], m.verdicts),
      h("h3", {}, "Tracked brands"),
      table([
        { label: "Brand", cell: (b) => h("b", {}, b.label) },
        { label: "Sector", cell: (b) => b.sector },
        { label: "Match", cell: (b) => (b.ambiguous ? h("span", { title: "needs Bulgarian context, or an exact-label squat on a high-abuse TLD" }, "ambiguous") : "distinctive") },
        { label: "Phrases", cell: (b) => list(b.phrases) },
        { label: "crt.sh keywords", cell: (b) => list(b.query_keys) },
        { label: "Allow-listed", cell: (b) => list(b.official) },
      ], m.brands),
      h("details", {}, h("summary", {}, "Namesakes, TLD tiers, lure words and context markers"),
        h("p", {}, h("b", {}, "Namesakes (legitimate, unrelated organisations): ")), table([{ label: "Domain", cell: (x) => h("span", { class: "mono" }, x[0]) }, { label: "Why", cell: (x) => x[1] }], Object.entries(m.namesakes)),
        h("p", {}, h("b", {}, "High-abuse TLDs")), list(m.tld_high), h("p", {}, h("b", {}, "Moderate-abuse TLDs")), list(m.tld_moderate),
        h("p", {}, h("b", {}, "Bulgarian lure words")), list(m.lures_bg), h("p", {}, h("b", {}, "English lure words")), list(m.lures_en),
        h("p", {}, h("b", {}, "Bulgarian context markers")), list(m.bg_markers)),
      h("h3", {}, "Correlation"),
      h("p", {}, `Population: names with verdict ${corr.population.join(", ")}. A relationship is accepted if it shares a strong indicator, or if its total weight is at least ${corr.min_edge} from at least ${corr.min_kinds} indicator kinds${corr.require_non_weak ? ", at least one of them not weak" : ""}. Medium and weak indicators weigh base × ln(N / df); values shared by more than max_df names are suppressed as ecosystem noise. Campaigns are connected components; a sparse component (density below ${corr.chained_density} with 4+ names) is labelled chained.`),
      table([
        { label: "Indicator kind", cell: (r) => h("span", { class: "mono" }, r[0]) },
        { label: "Class", cell: (r) => r[1].class },
        { label: "Base weight", num: true, cell: (r) => r[1].base },
        { label: "max df", num: true, cell: (r) => r[1].max_df },
      ], Object.entries(corr.kinds)),
      h("h3", {}, "Provenance of the current analysis"),
      kv([
        ["Analysis", `#${p.analysis_id} · created ${dt(p.created_at)} UTC · as of ${dt(p.as_of)} UTC`],
        ["Software", `trawl ${p.software_version}`], ["Rules", p.rules_version],
        ["Correlation config SHA-256", h("span", { class: "mono break" }, p.correlation_sha256)],
        ["Dataset SHA-256", h("span", { class: "mono break" }, p.dataset_sha256)],
        ["Results SHA-256", h("span", { class: "mono break" }, p.results_sha256)],
        ["Input cut-offs", h("span", { class: "mono" }, `run ≤ ${p.cutoffs.run} · record ≤ ${p.cutoffs.record} · dns ≤ ${p.cutoffs.dns}`)],
      ]),
      h("p", { class: "muted", style: { "margin-top": "8px" } }, "To reproduce: export the snapshot for this analysis (trawl snapshot), verify it (trawl verify), and replay it (trawl replay) - the replay must produce the same results SHA-256."),
      h("h3", {}, "Network behaviour"),
      table([
        { label: "From", cell: (r) => h("b", {}, r.from) }, { label: "To", cell: (r) => h("span", { class: "mono break" }, r.to) },
        { label: "Purpose", cell: (r) => r.purpose }, { label: "Note", cell: (r) => h("span", { class: "muted" }, r.note) },
      ], m.network),
      h("h3", {}, "Independence"),
      h("p", {}, "All data is collected by this system from primary public sources (crt.sh, DNS). No third-party phishing feed, seed list, AI classification or external scoring is used at any stage. Earlier beta tools in this project consumed a public feed (detectopod); that dependency was removed by design."));
  };
  PAGES.methodology.title = "Methodology";

  async function notFound() { return h("div", { class: "errbox" }, "No such page. ", h("a", { href: "#/" }, "Go to the overview.")); }

  // ---------------------------------------------------------------- boot
  function fillProvenance() {
    const p = META.provenance;
    document.getElementById("prov-chip").textContent = `analysis #${p.analysis_id} · as of ${dt(p.as_of)} UTC · dataset ${short(p.dataset_sha256, 10)}`;
    document.getElementById("prov-side").replaceChildren(h("dl", {},
      h("dt", {}, "analysis"), h("dd", {}, `#${p.analysis_id}`),
      h("dt", {}, "as of"), h("dd", {}, `${dt(p.as_of)} UTC`),
      h("dt", {}, "rules"), h("dd", {}, p.rules_version),
      h("dt", {}, "dataset"), h("dd", { title: p.dataset_sha256 }, short(p.dataset_sha256, 16)),
      h("dt", {}, "results"), h("dd", { title: p.results_sha256 }, short(p.results_sha256, 16))));
  }
  async function boot() {
    buildNav();
    document.getElementById("jump").addEventListener("submit", (e) => {
      e.preventDefault();
      const q = document.getElementById("jump-q").value.trim().toLowerCase();
      if (q) go("domains", { q, verdict: "likely,possible,lead,weak,legitimate,none" });
    });
    addEventListener("keydown", (e) => {
      if (e.key === "/" && !/^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement?.tagName)) { e.preventDefault(); document.getElementById("jump-q").focus(); }
    });
    try {
      META = await api("meta");
      fillProvenance();
    } catch (e) {
      view.replaceChildren(h("div", { class: "errbox" }, h("b", {}, "No analysis available yet. "), String(e.message || e), h("p", { class: "muted" }, "The collector has not completed a cycle. Run `trawl cycle`, then reload.")));
      return;
    }
    addEventListener("hashchange", render);
    render();
  }
  boot();
})();
