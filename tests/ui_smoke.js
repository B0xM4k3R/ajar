// Runs the real web/app.js against a stub DOM and a state snapshot, then prints what it drew.
// Usage: node ui_smoke.js <state.json> <mac-to-expand>
const fs = require("fs"), vm = require("vm"), path = require("path");
const snap = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const expandMac = process.argv[3];
process.on("unhandledRejection", () => {});

const els = {};
let reportHtml = "", secHidden = null, afterClick = null;
const errors = [];
function fake() {
  const t = { classes: {}, dataset: {}, style: {}, children: [] };
  return new Proxy(t, {
    get(o, p) {
      if (p in o) return o[p];
      if (p === "classList") return { toggle: (c, on) => { o.classes[c] = !!on; }, add: c => { o.classes[c] = true; }, remove: c => { o.classes[c] = false; }, contains: c => !!o.classes[c] };
      if (p === "querySelector") return () => fake();
      if (p === "querySelectorAll") return () => [];
      if (["addEventListener", "setAttribute", "removeAttribute", "focus", "scrollIntoView", "appendChild", "remove", "click"].includes(p)) return () => {};
      if (p === "closest") return () => null;
      if (p === "getAttribute") return () => null;
      return undefined;
    },
    set(o, p, v) { o[p] = v; return true; },
  });
}
const document = { querySelector: s => (els[s] = els[s] || fake()), querySelectorAll: () => [], addEventListener() {}, body: fake() };
els["body"] = document.body;
const ctx = {
  document, console, URLSearchParams, encodeURIComponent, Date, Math, JSON, Set, Map, Promise, Intl, String, Number, Object, Array, RegExp, Error, parseInt, parseFloat, isNaN,
  CSS: { escape: s => String(s) },
  window: { scrollTo() {}, addEventListener() {} }, location: { href: "http://localhost/", hash: "" },
  navigator: {}, localStorage: { getItem() { return null; }, setItem() {} },
  prompt: () => null, confirm: () => true, alert() {}, AbortController, clearTimeout() {}, setTimeout: () => 0, setInterval: () => 0,
  fetch: async url => ({ ok: true, status: 200, json: async () => (String(url).includes("/api/state") ? snap : { events: [], latest: 0 }), text: async () => "", blob: async () => ({}) }),
};
vm.createContext(ctx);
const code = fs.readFileSync(path.join(__dirname, "..", "web", "app.js"), "utf8") +
  "\n;globalThis.__t = { render, renderSettings, renderReport, openDevice, showTab, expanded, get data() { return data; } };";
try { vm.runInContext(code, ctx); } catch (e) { errors.push("load: " + e.stack); }

(async () => {
  const tick = () => new Promise(r => setImmediate(r));
  for (let i = 0; i < 5; i++) await tick();
  try {
    const t = ctx.__t;
    if (expandMac) t.expanded.add(expandMac);
    t.render(snap);
    t.showTab("settings");
    t.renderSettings(true);
    t.showTab("report");
    reportHtml = (els["#report"] && els["#report"].innerHTML) || "";
    t.showTab("security");
    secHidden = els["#security"].hidden;
    t.expanded.clear();
    t.showTab("security");
    t.openDevice(expandMac);                 // what clicking a node on the map does
    afterClick = { expanded: t.expanded.has(expandMac), devicesHidden: els["#devices"].hidden, securityHidden: els["#security"].hidden };
  } catch (e) { errors.push("render: " + e.stack); }
  const html = s => (els[s] && els[s].innerHTML) || "";
  process.stdout.write(JSON.stringify({
    errors, report: reportHtml, map: html("#map"), afterClick, list: html("#list"), settings: html("#settings"), security: html("#securityContent"),
    bodyClasses: document.body.classes, roleBadge: (els["#roleBadge"] || {}).textContent || "",
  }));
})();
