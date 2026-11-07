// ajar dashboard. Polls /api/state and renders the Devices, WiFi and Security tabs.
const $ = s => document.querySelector(s);
const enc = encodeURIComponent;
const esc = s => String(s ?? "").replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const short = s => String(s || "").split(".")[0];
const isMacLike = s => !!s && (/^([0-9a-f]{2}[:-]?){5}[0-9a-f]{2}$/i.test(s) || /^[0-9a-f]{12}$/i.test(s));
const cut = (s, n) => (s.length > n ? s.slice(0, n - 1) + "…" : s);
const nameOf = d => {
  const candidates = [
    d.name,
    short(d.hostname),
    d.audit && d.audit.info && d.audit.info.name,
    d.audit && d.audit.info && short(d.audit.info.host),
    d.audit && d.audit.info && d.audit.info.model,
    d.vendor
  ];
  for (const c of candidates) {
    if (c && !isMacLike(c)) return c;
  }
  return d.mac.startsWith("ip:") ? d.ip : d.mac;
};
const tail = d => "." + String(d.ip).split(".").pop();
const status = d => {
  if (!d.online) return "off";
  const bad = issuesOf(d).some(f => f.level === "high" || (f.id && (f.id.startsWith("cve_") || f.id === "arp_spoof")));
  if (bad) return "bad";
  return d.approved ? "ok" : "new";
};
const issuesOf = d => (d.online && d.audit ? (d.audit.findings || []).filter(f => f.level !== "info" && !(d.accepted || []).includes(f.id)) : []);
// Severity used for badges: known-exploited counts in full; a distribution package may already be patched.
const cveScore = c => (c.kev ? Math.max(c.cvss, 9) : c.cvss - (c.maybe_patched ? 2 : 0));
const cveBadge = (a) => {
  if (!a || !a.cves || !a.cves.length) return "";
  const exploited = a.cves.filter(c => c.kev).length;
  const crit = a.cves.filter(c => !c.kev && cveScore(c) >= 9.0).length;
  const high = a.cves.filter(c => !c.kev && cveScore(c) >= 7.0 && cveScore(c) < 9.0).length;
  if (exploited) return `<span class="tag high">Exploited in the wild</span>`;
  if (crit) return `<span class="tag high">${crit} Critical CVE${crit>1?'s':''}</span>`;
  if (high) return `<span class="tag medium">${high} High CVE</span>`;
  return "";
};

const KIND_NAMES = { iot: "smart-home", tv: "smart TV", personal: "phone or computer", pi: "Raspberry Pi",
  router: "router", printer: "printer", other: "unknown type", "this device": "this device" };
let data = null;
let renaming = null;
const expanded = new Set();
const when = t => (t ? new Date(t * 1000).toLocaleString() : "");

function ago(t, now) {
  if (!t) return "never";
  const s = Math.max(0, now - t);
  if (s < 60) return "just now";
  if (s < 3600) return Math.round(s / 60) + " min ago";
  if (s < 86400) return Math.round(s / 3600) + " h ago";
  return Math.round(s / 86400) + " days ago";
}

function drawMap(devices, gateway, scanning) {
  const cx = 180, cy = 180;
  const router = devices.find(d => d.ip === gateway);
  const others = devices.filter(d => d.ip !== gateway);
  const ring1 = others.slice(0, 10), ring2 = others.slice(10, 30);
  let out = "";
  const place = (list, r, offset) => list.forEach((d, i) => {
    const a = (i / list.length) * Math.PI * 2 - Math.PI / 2 + offset;
    const x = (cx + r * Math.cos(a)).toFixed(1), y = cy + r * Math.sin(a), st = status(d);
    out += `<line x1="${cx}" y1="${cy}" x2="${x}" y2="${y.toFixed(1)}"/>`;
    if (issuesOf(d).length) out += `<circle class="issue" cx="${x}" cy="${y.toFixed(1)}" r="${st === "new" || st === "bad" ? 15 : 11}"/>`;
    if (st === "new" || st === "bad") out += `<circle class="halo" cx="${x}" cy="${y.toFixed(1)}" r="11"/>`;
    out += `<circle class="node ${st}" cx="${x}" cy="${y.toFixed(1)}" r="7"><title>${esc(nameOf(d))} (${esc(d.ip)})</title></circle>`;
    out += `<text x="${x}" y="${(y + 22).toFixed(1)}">${esc(cut(nameOf(d), 11))}</text>`;
    out += `<text class="tail" x="${x}" y="${(y + 31).toFixed(1)}">${esc(tail(d))}</text>`;
  });
  place(ring1, 95, 0);
  place(ring2, 148, Math.PI / Math.max(ring2.length, 1));
  if (others.length > 30) out += `<text x="${cx}" y="376">+${others.length - 30} more in the list</text>`;
  if (scanning) out += `<circle class="pulse" cx="${cx}" cy="${cy}" r="14"/>`;
  if (router && issuesOf(router).length) out += `<circle class="issue" cx="${cx}" cy="${cy}" r="19"/>`;
  if (router && !router.approved) out += `<circle class="halo" cx="${cx}" cy="${cy}" r="16"/>`;
  out += `<rect class="hub" x="${cx - 12}" y="${cy - 12}" width="24" height="24" rx="5"/>`;
  out += `<text x="${cx}" y="${cy + 30}">router</text>`;
  $("#map").innerHTML = out;
}

function ring(score, size) {
  const r = size / 2 - 5, c = 2 * Math.PI * r, f = typeof score === "number" ? Math.max(0, Math.min(100, score)) / 100 : 0;
  return `<svg class="ring" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" aria-hidden="true">
    <circle class="track" cx="${size / 2}" cy="${size / 2}" r="${r}" stroke-width="7"/>
    <circle class="val" cx="${size / 2}" cy="${size / 2}" r="${r}" stroke-width="7" stroke-dasharray="${(c * f).toFixed(1)} ${c.toFixed(1)}"
      transform="rotate(-90 ${size / 2} ${size / 2})"/>
    <text x="${size / 2}" y="${size / 2 + size * 0.11}" font-size="${size * 0.3}">${score}</text></svg>`;
}

function fixItem(i, steps) {
  return `<li><span class="gain">+${i.points}</span><span><b>${esc(i.title)}</b>
    <span class="sub">${i.level === "high" ? "High risk. " : ""}${esc(i.problem)}${i.where ? ` (${esc(i.where)})` : ""}</span></span>
    ${steps ? `<p class="how">How: ${esc(i.fix)}</p>` : ""}
    ${steps && i.mac && !savedView() ? `<button class="quiet mini" data-accept="${esc(i.mac)}|${esc(i.id)}" title="Stop counting this against your score">Accept this risk</button>` : ""}</li>`;
}
async function setRisk(body) {
  await fetch("/api/settings" + (netQ() ? "?" + netQ() : ""), { method: "POST",
    headers: { "X-Ajar": "1", "Content-Type": "application/json" }, body: JSON.stringify(body) });
  load(true);
}
function acceptRisk(key) {
  const i = key.indexOf("|"), mac = key.slice(0, i), id = key.slice(i + 1);
  const reason = prompt("Accepting a risk stops it counting against your score. It stays listed so you can undo it.\n\nWhy is it OK? (optional)", "");
  if (reason !== null) setRisk({ accept: { mac, id, reason } });
}
function undoRisk(key) {
  const i = key.indexOf("|");
  setRisk({ unaccept: { mac: key.slice(0, i), id: key.slice(i + 1) } });
}
function acceptedBlock(sec) {
  if (!sec.accepted || !sec.accepted.length) return "";
  return `<div class="block"><h3>Accepted risks</h3><p class="sub">You decided to live with these. They don't count against the score.</p>
    <ul class="fixes accepted">${sec.accepted.map(i => `<li><span class="gain">–</span><span><b>${esc(i.title)}</b>
      <span class="sub">${esc(i.problem)}${i.reason ? ` Your reason: ${esc(i.reason)}` : ""}</span></span>
      ${savedView() ? "" : `<button class="quiet mini" data-unaccept="${esc(i.mac)}|${esc(i.id)}">Undo</button>`}</li>`).join("")}</ul></div>`;
}

function summaryLine(sec) {
  const total = sec.issues.reduce((t, i) => t + i.points, 0);
  return sec.issues.length
    ? `${sec.issues.length} fix${sec.issues.length === 1 ? "" : "es"} worth ${total} points`
    : "Nothing to fix in what ajar checked.";
}

function renderInet(h) {
  const box = $("#inet");
  if (!box) return;
  if (!h || h.status === "unknown") { box.hidden = true; return; }
  box.hidden = false;
  box.className = h.status === "down" ? "down" : "";
  const when = t => new Date(t * 1000).toLocaleString([], { weekday: "short", hour: "numeric", minute: "2-digit" });
  const o = h.last_outage;
  if (h.status === "down") {
    box.innerHTML = `<b>Internet is down.</b> <span>Looks like ${esc(h.cause || "a network problem")}.</span>
      ${o ? `<span class="sub">Since ${esc(when(o.start))}.</span>` : ""}`;
    return;
  }
  const bits = [`<b>Internet is up.</b>`];
  if (h.uptime_7d != null) bits.push(`<span>${h.uptime_7d >= 99.95 ? "100" : h.uptime_7d}% uptime this week</span>`);
  if (h.latency != null) bits.push(`<span class="sub">${h.latency} ms</span>`);
  if (o && !o.ongoing) bits.push(`<span class="sub">Last outage: ${esc(when(o.start))}, ${esc(o.cause || "")}</span>`);
  box.innerHTML = bits.join(" ");
}

function renderScorecard(sec) {
  const card = $("#scorecard");
  if (!card) return 0;
  card.hidden = false;
  card.className = "g-" + sec.grade;
  if (sec.unscored) {
    card.className = "";
    card.innerHTML = `<div class="scorehead">${ring("–", 64)}<div><h2>Security score: not checked yet</h2>
      <p class="sub">Needs ${esc(sec.missing.join("; "))}.</p></div></div>`;
    return 0;
  }
  card.innerHTML = `<div class="scorehead">${ring(sec.score, 64)}<div>
      <h2>Security score: ${sec.grade}${sec.partial ? " (partial)" : ""}</h2>
      <p class="sub">${esc(summaryLine(sec).replace(/\.$/, ""))}${sec.partial ? ". Not checked yet: " + esc(sec.missing.join("; ")) : ""}.</p></div></div>
    ${sec.issues.length ? `<ul class="fixes">${sec.issues.slice(0, 3).map(i => fixItem(i, false)).join("")}</ul>` : ""}
    <button class="quiet scorecard-btn" data-tab="security">${sec.issues.length > 3 ? `See all ${sec.issues.length} fixes and checks` : "See fixes and checks"}</button>`;
  return sec.issues.length;
}

function sparkline(hist) {
  if (hist.length < 2) return "";
  const t0 = hist[0][0], t1 = hist[hist.length - 1][0] || t0 + 1, span = Math.max(1, t1 - t0);
  const pts = hist.map(([t, s]) => `${(30 + ((t - t0) / span) * 320).toFixed(1)},${(70 - s * 0.6).toFixed(1)}`).join(" ");
  const day = t => new Date(t * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric" });
  return `<svg class="spark" viewBox="0 0 360 92" role="img" aria-label="Score over time">
    <line class="base" x1="30" y1="70" x2="350" y2="70"/><line class="base" x1="30" y1="10" x2="350" y2="10" stroke-dasharray="2 3"/>
    <text x="24" y="13" text-anchor="end">100</text><text x="24" y="73" text-anchor="end">0</text>
    <polyline points="${pts}"/><text x="30" y="86">${day(t0)}</text><text x="350" y="86" text-anchor="end">${day(t1)}</text></svg>`;
}

function exposureBlock(ex) {
  const head = `<div class="block"><h3>Open to the internet</h3>`;
  const manual = `<p class="sub">Port forwards set up by hand in the router's own settings usually don't show here.</p>`;
  if (!ex) return head + `<p class="sub">Not checked yet. It runs with Check services.</p></div>`;
  if (ex.status === "no_upnp") return head + `<p>Your router doesn't answer UPnP, so apps and devices can't open ports to the internet on it by themselves.</p>${manual}</div>`;
  const on = ex.mappings.filter(m => m.enabled);
  let html = head;
  if (ex.status === "error") html += `<p class="sub">${esc(ex.error || "The router didn't answer.")}${ex.stale ? " Showing the list from the last check." : ""}</p>`;
  if (!ex.reachable) html += `<p class="hint">Your router's own internet address is ${ex.wan === "cgnat" ? "shared with other customers by your provider" : "private, so another router sits between it and the internet"}. The ports below probably can't be reached from the internet unless that is set up too.</p>`;
  if (ex.status === "listed" && !on.length) html += `<p>UPnP is on, but nothing is open to the internet right now.</p>`;
  if (on.length || ex.mappings.length) html += `<p>${on.length ? `Your router lets the internet reach ${plural(on.length, "port")} on your devices:` : ""}</p>
    <ul class="exposed">${ex.mappings.map(m => `<li class="${m.enabled ? "" : "off"}">
      <span class="port">${esc(m.proto)} ${m.ext}</span>
      <span><b>${esc(m.device)}</b>, port ${m.port}${m.service ? ` (${esc(m.service)})` : ""}${
        m.risky && m.enabled && ex.reachable ? ` <span class="lvl high">High risk</span>` : ""}
        <span class="sub">${[m.known ? esc(m.client) : "not a device ajar knows", m.desc ? `"${esc(m.desc)}"` : "",
          m.remote ? "from one address only" : "", m.enabled ? (m.lease ? "temporary" : "until removed") : "switched off"]
          .filter(Boolean).join(" · ")}</span></span></li>`).join("")}</ul>`;
  return html + manual + "</div>";
}

function reportBtn() {
  return `<div class="actions" style="margin:0 0 4px"><button class="quiet" data-report="1">Download audit report</button>
    <span class="sub">A single HTML file you can save, print or share.</span></div>`;
}

async function downloadReport(btn) {
  const label = btn.textContent;
  btn.disabled = true; btn.textContent = "Preparing…";
  try {
    const r = await fetch("/api/report" + (netQ() ? "?" + netQ() : ""));
    if (!r.ok) throw new Error("HTTP " + r.status);
    const blob = await r.blob();
    const cd = r.headers.get("Content-Disposition") || "";
    const m = cd.match(/filename="?([^"]+)"?/);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = m ? m[1] : "ajar-audit.html";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    btn.textContent = "Downloaded ✓";
  } catch (e) {
    console.error(e);
    btn.textContent = "Couldn't build report";
  } finally {
    btn.disabled = false;
    setTimeout(() => { btn.textContent = label; }, 2500);
  }
}

function renderSecurity(sec) {
  if (sec.unscored) {
    $("#security").className = "";
    $("#securityContent").innerHTML = reportBtn() + `<div class="block"><div class="scorehead">${ring("–", 84)}<div><h2>Not checked yet</h2>
      <p>The score needs ${esc(sec.missing.join("; "))}.</p></div></div></div>`;
    return;
  }
  const h = sec.history || [];
  const prev = [...h].reverse().find(x => x[1] !== sec.score);
  const trend = prev ? `${sec.score > prev[1] ? "Up" : "Down"} from ${prev[1]} on ${new Date(prev[0] * 1000).toLocaleDateString()}.` : "";
  const icon = { pass: "✓", fail: "✗", unknown: "?" };
  const lost = [sec.lost.wifi ? `${sec.lost.wifi} on WiFi` : "", sec.lost.devices ? `${sec.lost.devices} on devices` : "",
    sec.lost.internet ? `${sec.lost.internet} on what's open to the internet` : ""].filter(Boolean);
  $("#security").className = "g-" + sec.grade;
  $("#securityContent").innerHTML = reportBtn() + `
    <div class="block"><div class="scorehead">${ring(sec.score, 84)}<div>
      <h2>Grade ${sec.grade}</h2>
      <p>${esc(summaryLine(sec))}.${lost.length ? ` Points lost: ${lost.join(", ")}.` : ""}</p>
      ${trend ? `<p class="sub">${esc(trend)}</p>` : ""}</div></div>
      ${sec.partial ? `<p class="hint">Partial score. Not checked yet: ${esc(sec.missing.join("; "))}.</p>` : ""}
      ${sparkline(h)}</div>
    <div class="block"><h3>Fixes, biggest first</h3>
      ${sec.issues.length ? `<ul class="fixes">${sec.issues.map(i => fixItem(i, true)).join("")}</ul>`
        : `<p class="sub">Nothing to fix in what ajar checked.</p>`}</div>
    ${acceptedBlock(sec)}
    ${exposureBlock(sec.exposure)}
    ${sec.optional.length ? `<div class="block"><h3>Optional upgrades</h3><ul class="fixes">${sec.optional.map(t =>
      `<li><span class="gain">0</span><span>${esc(t)}</span></li>`).join("")}</ul></div>` : ""}
    <div class="block"><h3>Checks</h3><ul class="checks">${sec.checks.map(c =>
      `<li class="${c.status}"><span class="st">${icon[c.status]}</span><span>${esc(c.label)}${c.status === "unknown" ? " (not checked yet)" : ""}</span></li>`).join("")}</ul>
      ${sec.wps_unknown_reason ? `<p class="sub">${esc(sec.wps_unknown_reason)}</p>` : ""}</div>
    <div class="block"><h3>How the score works</h3>
      <p class="sub">It starts at 100 and loses points for each security problem, by how much it exposes you.</p>
      <ul class="rubric"><li>30: WiFi with no password, WEP, or old WPA; a camera stream or admin page open with no login; each risky service the router opens to the internet</li>
        <li>15: Telnet, Android debugging (ADB), anonymous FTP, a share anyone can change, NFS open to all, old SMBv1 file sharing, sensitive files on an open share, a fake copy of your WiFi</li>
        <li>8: a share anyone can read, VNC, old WPA/TKIP mode, WPS on</li>
        <li>6: FTP, Remote Desktop, UPnP, unencrypted MQTT, password-less smart-plug control, smart-home devices sharing a network with computers, a mismatched access point, a limited NFS export</li>
        <li>3 per unapproved device, up to 12</li>
        <li>3 per other port open to the internet (game consoles, media servers), up to 9</li></ul>
      <p class="sub">Devices seen in the last 7 days count even while asleep. Grades: A 90+, B 80+, C 70+, D 60+.</p>
    </div>`;
}

const SENSITIVE_NAME = /(password|passwd|secret|credential|\.env$|id_rsa|\.pem$|\.key$|\.kdbx$|wallet|\.sql$|tax|invoice|\bw-?2\b|\b1099\b|payroll|bank|statement|budget|backup|\.bak$)/i;
const fsize = n => (n == null ? "" : n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(0) + " KB"
  : n < 1073741824 ? (n / 1048576).toFixed(1) + " MB" : (n / 1073741824).toFixed(1) + " GB");

function fileList(entries) {
  const dirs = entries.filter(e => e.is_dir), files = entries.filter(e => !e.is_dir);
  const row = e => `<li class="${e.is_dir ? "dir" : ""}${!e.is_dir && SENSITIVE_NAME.test(e.name) ? " risk" : ""}">
    <span class="fn">${esc(e.name)}${e.is_dir ? "/" : ""}</span>
    ${!e.is_dir && SENSITIVE_NAME.test(e.name) ? `<span class="tag high">sensitive</span>` : ""}
    <span class="sub">${e.is_dir ? "folder" : esc(fsize(e.size))}</span></li>`;
  return `<ul class="files">${[...dirs, ...files].map(row).join("")}</ul>`;
}

function shareContents(d, a) {
  let html = "";
  for (const s of (a.shares || [])) {
    if (!s.files) continue;
    const ex = s.exposed || {};
    html += `<div class="sharebox"><div class="sharehead"><b>${esc(s.name)}</b>
      <span class="sub">${s.access === "read/write" ? "anyone can read & change" : "anyone can read"}, no password</span></div>
      ${ex.sensitive ? `<p class="hint">This open share exposes ${esc(describeCats(ex))}. Move those files somewhere private.</p>` : ""}
      ${s.files.length ? fileList(s.files) : `<p class="sub">Empty, or nothing listable.</p>`}
      <p class="openwith">Open it: <a href="smb://${esc(d.ip)}/${esc(s.name)}">smb://${esc(d.ip)}/${esc(s.name)}</a>
        <span class="sub">(on Windows, type <code>\\\\${esc(d.ip)}\\${esc(s.name)}</code> in File Explorer)</span></p></div>`;
  }
  if (a.ftp_files) {
    const ex = a.ftp_exposed || {};
    html += `<div class="sharebox"><div class="sharehead"><b>Anonymous FTP</b>
      <span class="sub">anyone can log in without a password</span></div>
      ${ex.sensitive ? `<p class="hint">This FTP server exposes ${esc(describeCats(ex))}.</p>` : ""}
      ${fileList(a.ftp_files)}
      <p class="openwith">Open it: <a href="ftp://${esc(d.ip)}/">ftp://${esc(d.ip)}/</a></p></div>`;
  }
  return html ? `<div class="contents"><h4>What's being served</h4>${html}</div>` : "";
}

const CAT_WORDS = { credentials: "what looks like passwords or keys", financial: "financial records",
  backups: "backups", documents: "documents", photos: "photos and videos" };
function describeCats(ex) {
  const parts = (ex.categories || []).map(c => CAT_WORDS[c] || c);
  const phrase = parts.length <= 1 ? (parts[0] || "") : parts.slice(0, -1).join(", ") + " and " + parts[parts.length - 1];
  return phrase + (ex.examples && ex.examples.length ? ` (${ex.examples.slice(0, 2).join(", ")})` : "");
}

function detail(d, now) {
  const a = d.audit, inf = (a && a.info) || {};
  const facts = [
    ["Name", d.name ? d.name + " (your name)" : nameOf(d)],
    ["Hostname", d.hostname || inf.host], ["IP address", d.ip],
    ["MAC address", d.mac.startsWith("ip:") ? "" : d.mac],
    ["Vendor", d.vendor], ["Type", KIND_NAMES[d.kind] || d.kind], ["Maker", inf.maker], ["Model", inf.model],
    ["Screen size", inf.size_in ? inf.size_in + " inch" : ""],
    ["Status", savedView() ? "Last seen " + when(d.last_seen) : d.online ? "Online now" : "Offline, last seen " + when(d.last_seen)],
    ["First seen", when(d.first_seen)], ["Approved", d.approved ? "Yes" : "Not yet"],
  ];
  if (a) {
    facts.push(["Open ports", a.ports.map(p => `${p.name} (${p.port})`).join(", ") || "None found"]);
    facts.push(["Ports checked", a.depth === "deep" ? `1 to 10,000 (deep check${a.deep_at ? ", " + ago(a.deep_at, now) : ""}; redone weekly)` : `${18} common ports.`]);
    facts.push(["Shares", a.shares.map(s => `${s.name} (${s.access === "none" ? "needs login" : s.access})`).join(", ")]);
    facts.push(["Announces", (inf.bonjour || []).join(", ")]);
    facts.push(["OS guess", a.os ? `${a.os.name} (${a.os.accuracy}% match)` : ""]);
    facts.push(["Checked", ago(a.scanned, now)]);
    const ex = data && data.security && data.security.exposure;
    const open = ex ? ex.mappings.filter(m => m.enabled && m.client === d.ip) : [];
    if (open.length) facts.push(["Open to the internet", open.map(m => `${m.proto} ${m.ext}${m.service ? " (" + m.service + ")" : ""}`).join(", ") + (ex.reachable ? "" : " (probably not reachable)")]);
    if (a.web) {
      const st = a.web.auth === "open" ? "opens with NO login" : a.web.auth === "basic" ? "asks for a login" : a.web.auth === "login_form" ? "shows a login page" : "reachable";
      facts.push(["Admin page", `${st}${a.web.plain ? ", over plain HTTP" : a.web.scheme === "https" ? ", over HTTPS" : ""}`]);
    }
    if (a.rtsp && a.rtsp.open) facts.push(["Camera stream", "plays with no password"]);
  } else {
    facts.push(["Services", "Not checked yet. Tap Check services."]);
  }
  
  const notes = a ? a.findings : [];
  const lvl = { high: "High", medium: "Medium", info: "Info" };
  const webUrl = a && a.web && a.web.url;

  // --- CVEs ---
  let cveHtml = "";
  if (a && a.cves && a.cves.length) {
    cveHtml = `<h4 style="color:var(--high)">Vulnerabilities</h4><ul class="files">` +
      a.cves.map(c => `<li class="risk"><span class="fn">${esc(c.id)}</span><span class="tag ${c.kev || cveScore(c) >= 9 ? "high" : "medium"}">CVSS ${c.cvss}</span>
        ${c.kev ? '<span class="tag high">Attackers are using this now</span>' : ""}
        ${c.maybe_patched && !c.kev ? `<span class="tag" title="Linux distributions usually fix security bugs without changing the version number, so this match may be a false alarm. Run the system's updates to be sure.">May already be patched by ${esc(c.vendor || "your distribution")}</span>` : ""}
        ${c.port ? `<span class="sub">port ${c.port}</span>` : ""}</li>`).join("") + `</ul>`;
  }

  // --- Probes ---
  let probesHtml = "";
  const probes = a ? (a.probes || {}) : {};
  const probeEntries = Object.entries(probes);
  if (probeEntries.length) {
    probesHtml = `<h4>Behind the port</h4><dl>` + probeEntries.map(([port, data]) => {
      let val = [];
      if (data.http) val.push(`${esc(data.http.title || data.http.server || "Responded")}${data.http.default_banner ? ' <span class="lvl high">Default Login</span>' : ''}`);
      if (data.tls) val.push(`${esc(data.tls.issuer || "Unknown cert")} (${data.tls.version})`);
      if (data.ssh) val.push(`${esc(data.ssh.software || "Unknown")}${data.ssh.legacy ? ' <span class="lvl medium">Legacy</span>' : ''}`);
      if (data.snmp) val.push(`${esc(data.snmp.sysdescr || "public")}`);
      if (data.banner) val.push(esc(cut(data.banner, 60)));
      return val.length ? `<dt>Port ${port}</dt><dd>${val.join("<br>")}</dd>` : "";
    }).join("") + `</dl>`;
  }

  // --- Credentials ---
  let credHtml = "";
  if (d.online && a && a.probes) {
    const isAuth = d.cred_consent || false;
    const res = a.default_cred_result;
    let statusText = isAuth ? "Authorized. Waiting for next Check services." : "Not authorized.";
    let statusClass = "sub";

    if (res && !res.skipped) {
      if (res.success) {
        statusText = `<b style="color:var(--high)">VULNERABLE!</b> Factory default credentials worked.`;
        statusClass = "text high";
      } else if (res.lockout) {
        statusText = `<b style="color:var(--med)">LOCKOUT SUSPECTED.</b> Paused after 3 attempts.`;
        statusClass = "text medium";
      } else {
        statusText = `✅ <b style="color:var(--ok)">Safe.</b> Tried ${res.tried.length} credentials. None worked.`;
        statusClass = "text ok";
      }
    } else if (res && res.skipped) {
       statusText = `Skipped: ${res.skipped}`;
    }

    credHtml = `<div class="credbox">
      <b>Credential Test (Tier C)</b>
      <p class="${statusClass}" style="margin:4px 0 8px">${statusText}</p>
      <button class="quiet" data-act="auth_cred" data-mac="${esc(d.mac)}" data-auth="${isAuth}">${isAuth ? "Revoke Authorization" : "Authorize Test"}</button>
    </div>`;
  }

  return `<div class="detail"><dl>${facts.filter(f => f[1]).map(([k, v]) =>
      `<dt>${esc(k)}</dt><dd>${esc(v)}${k === "Admin page" && webUrl ? ` — <a href="${esc(webUrl)}">open it</a>` : ""}</dd>`).join("")}</dl>` +
    (notes.length ? `<ul>${notes.map(f => {
        const ok = (d.accepted || []).includes(f.id);
        return `<li${ok ? ' class="accepted"' : ""}><span class="lvl ${f.level}">${lvl[f.level]}</span>${esc(f.text)}${ok ? ' <span class="tag">Accepted</span>' : ""}
        ${f.level !== "info" && !savedView() ? `<button class="quiet mini" ${ok ? `data-unaccept="${esc(d.mac)}|${esc(f.id)}">Undo` : `data-accept="${esc(d.mac)}|${esc(f.id)}">Accept this risk`}</button>` : ""}</li>`; }).join("")}</ul>` : "") +
    cveHtml +
    probesHtml +
    (a ? shareContents(d, a) : "") +
    credHtml +
    `</div>`;
}

function row(d, now) {
  const a = d.audit;
  const svc = a ? [...new Set([...a.ports.map(p => p.name), ...(a.upnp_igd ? ["UPnP router control"] : []), ...(a.upnp_media ? ["UPnP media server"] : [])])] : [];
  const shares = a ? a.shares.map(s => `${esc(s.name)} (${s.access === "none" ? "needs login" : esc(s.access)})`) : [];
  const inf = (a && a.info) || {};
  const about = [inf.maker && inf.model && !inf.model.startsWith(inf.maker) ? inf.maker + " " + inf.model : inf.model || inf.maker, inf.size_in ? inf.size_in + " inch" : ""].filter(Boolean).join(", ");
  const open = expanded.has(d.mac);
  const where = [d.ip, KIND_NAMES[d.kind] || d.kind, d.vendor && d.vendor !== nameOf(d) && d.vendor.toLowerCase() !== String(d.kind).toLowerCase() ? d.vendor : ""].filter(Boolean);
  return `
    <li class="${status(d)}">
      <span class="dot"></span>
      ${renaming === d.mac
        ? `<form class="rename" data-mac="${esc(d.mac)}"><input name="n" maxlength="40" value="${esc(d.name || nameOf(d))}" aria-label="Device name"><button>Save</button><button type="button" class="quiet" data-act="cancel">Cancel</button></form>`
        : `<button class="name" data-act="toggle" data-mac="${esc(d.mac)}" aria-expanded="${open}">${esc(nameOf(d))}${cveBadge(a)}</button>`}
      <span class="meta">${where.map(esc).join(", ")}${d.online ? "" : ", last seen " + ago(d.last_seen, now)}
        ${d.mac.startsWith("ip:") ? "" : `<br><span class="mac">${esc(d.mac)}</span>`}</span>
      ${about ? `<span class="extra">${esc(about)}</span>` : ""}
      ${svc.length ? `<span class="extra">Open: ${svc.map(esc).join(", ")}</span>` : ""}
      ${shares.length ? `<span class="extra">Shares: ${shares.join(", ")}</span>` : ""}
      <span class="actions">
        ${d.online && !d.approved ? `<button data-act="approve" data-mac="${esc(d.mac)}">Approve</button>` : ""}
        <button class="quiet" data-act="rename" data-mac="${esc(d.mac)}">Rename</button>
      </span>
      ${open ? detail(d, now) : ""}
    </li>`;
}

function render(res) {
  data = res;
  const viewer = res.role === "viewer";
  document.body.classList.toggle("viewer", viewer);
  $("#roleBadge").textContent = viewer ? "View only" : "";
  const { state, devices } = res;
  const online = devices.filter(d => d.online);
  const fresh = online.filter(d => !d.approved);
  const wf = (res.wifi && res.wifi.result) ? res.wifi.result.findings : [];
  const nIssues = res.security ? renderScorecard(res.security) : 0;
  renderInet(res.health);
  if (res.security) renderSecurity(res.security);
  const nWifi = wf.filter(f => f.level !== "info").length;
  $("#wifiBadge").innerHTML = nWifi ? `<span class="badge">${nWifi}</span>` : "";
  $("#sub").textContent = state.scanning ? `${state.phase || "Working"}…`
    : state.subnet ? `${state.subnet}, scanned ${ago(state.last_scan, state.now)}` + (state.last_audit ? `, services checked ${ago(state.last_audit, state.now)}` : "")
    : "Waiting for first scan";
  $("#count").innerHTML = (savedView() ? `<b>${online.length}</b> seen on the last visit` : `<b>${online.length}</b> online`) +
    (fresh.length ? `, <b>${fresh.length}</b> new` : "") +
    (nIssues ? `, <b>${nIssues}</b> to review` : "");
  $("#approveAll").hidden = !fresh.length;
  const busy = state.scanning || (res.wifi && res.wifi.scanning);
  $("#scan").disabled = $("#audit").disabled = $("#fullAudit").disabled = busy;
  $("#stopScan").style.display = state.scanning ? "" : "none";
  $("#scan").textContent = state.scanning && state.phase === "Scanning devices" ? "Mapping…" : "Map Network";
  $("#audit").textContent = state.scanning && state.phase !== "Scanning devices" ? "Scanning…" : "Standard Scan";
  const msgs = [state.error, state.audit_note, state.warning].filter(Boolean);
  const tls = state.tls || {};
  $("#banner").innerHTML = (tls.on === false ? `<div class="banner warn">Plain HTTP: anyone on your WiFi could read this dashboard and its password. ${esc(tls.why || "")}</div>` : "") +
    msgs.map(m => `<div class="banner">${esc(m)}</div>`).join("");
  $("#footer").innerHTML = tls.on ? `Secure connection (HTTPS, self-signed). Certificate fingerprint:<br><span class="fp">${esc(tls.fingerprint)}</span>` : "Not encrypted (plain HTTP).";
  drawMap(online, state.gateway, state.scanning);
  $("#list").innerHTML = devices.length ? devices.map(d => row(d, state.now)).join("") : `<li class="empty">No devices yet. The first scan takes under a minute.</li>`;
  if (res.wifi) renderWifi(res.wifi, state.now);
  renderProgress(state, res.wifi);
  const box = renaming && $(".rename input");
  if (box) { box.focus(); box.select(); }
}


// ---------------------------------------------------------------- WiFi tab
const CH5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165];
const wexp = new Set();
const quality = dbm => (dbm >= -55 ? "excellent" : dbm >= -67 ? "good" : dbm >= -75 ? "fair" : "weak");
const privateMac = m => !!m && (parseInt(m[1], 16) & 2) === 2;
const gradeOf = (n, label) => (n.aps.find(a => a.sec.label === label) || n.aps[0]).sec.grade;
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;

function bars(dbm) {
  const on = dbm >= -55 ? 4 : dbm >= -67 ? 3 : dbm >= -75 ? 2 : 1;
  return `<svg class="bars" width="16" height="11" viewBox="0 0 16 11" aria-hidden="true">${[0, 1, 2, 3].map(i =>
    `<rect class="${i < on ? "on" : ""}" x="${i * 4}" y="${8 - i * 2.5}" width="3" height="${3 + i * 2.5}" rx="0.5"/>`).join("")}</svg>`;
}

function spanOf(a, fallback) {
  if (a.band === "2.4") return a.sec2 ? [Math.min(a.ch, a.sec2), Math.max(a.ch, a.sec2)] : [a.ch, a.ch];
  const w = a.width || fallback || 20;
  if (a.band === "5" && w > 20) {
    const blocks = { 40: [36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157].map(c => [c, c + 4]),
      80: [36, 52, 100, 116, 132, 149].map(c => [c, c + 12]), 160: [[36, 64], [100, 128]] }[w] || [];
    const b = blocks.find(([lo, hi]) => lo <= a.ch && a.ch <= hi);
    if (b) return b;
  }
  return [a.ch, a.ch];
}

function chart(b, nets) {
  const aps = [];
  nets.forEach(n => n.aps.forEach(a => { if (a.band === b.band) aps.push({ a, n }); }));
  aps.sort((p, q) => (p.n.mine - q.n.mine) || (p.a.dbm - q.a.dbm));
  // Find the strongest access point for EACH network, not just ours
  const strongest = {};
  aps.forEach(p => {
    if (!strongest[p.n.key] || p.a.dbm > strongest[p.n.key].a.dbm) {
      strongest[p.n.key] = p;
    }
  });
  const base = 104, hOf = dbm => Math.min(92, Math.max(5, ((dbm + 100) / 65) * 92));
  let out = "", labels = "";
  if (b.band === "2.4") {
    const x = c => 12 + (c + 1) * 21;
    aps.forEach(({ a, n }) => {
      const [lo, hi] = spanOf(a), h = hOf(a.dbm), l = x(lo - 2), r = x(hi + 2);
      const d = lo === hi ? `M${l},${base} Q${x(lo)},${base - 2 * h} ${r},${base} Z` : `M${l},${base} L${x(lo)},${base - h} L${x(hi)},${base - h} L${r},${base} Z`;
      out += `<path class="net${n.mine ? " mine" : ""}" d="${d}"><title>${esc(n.ssid || "Hidden")}, ch ${a.ch}, ${a.dbm} dBm</title></path>`;
      if (strongest[n.key] && a === strongest[n.key].a) labels += `<text class="lab" x="${x((lo + hi) / 2)}" y="${base - h - 5}">${esc(cut(n.ssid, 14))}</text>`;
    });
    let axis = "";
    for (let c = 1; c <= 13; c++) axis += `<text class="${[1, 6, 11].includes(c) ? "key" : ""}" x="${x(c)}" y="${base + 14}">${c}</text>`;
    const bx = x(b.best.lo);
    const pick = `<line class="best" x1="${bx}" y1="12" x2="${bx}" y2="${base}"/><text class="pick" x="${bx}" y="9">quietest</text>`;
    return `<svg class="chart" viewBox="0 0 360 124" role="img" aria-label="2.4 GHz networks by channel">${pick}${out}<line class="axis" x1="0" y1="${base}" x2="360" y2="${base}"/>${labels}${axis}</svg>`;
  }
  const sw = 336 / CH5.length, x = i => 12 + i * sw, idx = c => CH5.indexOf(c);
  const dfs = `<rect class="dfs" x="${x(idx(52))}" y="14" width="${(idx(144) - idx(52) + 1) * sw}" height="${base - 14}"/><text x="${x(idx(52)) + ((idx(144) - idx(52) + 1) * sw) / 2}" y="24">DFS (shared with radar)</text>`;
  aps.forEach(({ a, n }) => {
    const [lo, hi] = spanOf(a, n.mine && b.width_assumed ? b.width : 0), i0 = idx(lo), i1 = idx(hi);
    if (i0 < 0 || i1 < 0) return;
    const h = hOf(a.dbm);
    out += `<rect class="net${n.mine ? " mine" : ""}" x="${x(i0) + 1}" y="${base - h}" width="${(i1 - i0 + 1) * sw - 2}" height="${h}" rx="3"><title>${esc(n.ssid || "Hidden")}, ch ${a.ch}${a.width ? ", " + a.width + " MHz" : ""}, ${a.dbm} dBm</title></rect>`;
    if (strongest[n.key] && a === strongest[n.key].a) labels += `<text class="lab" x="${x(i0) + ((i1 - i0 + 1) * sw) / 2}" y="${base - h - 5}">${esc(cut(n.ssid, 14))}</text>`;
  });
  const axis = [36, 52, 100, 116, 132, 149, 165].map(c => `<text class="key" x="${x(idx(c)) + sw / 2}" y="${base + 14}">${c}</text>`).join("");
  const p0 = idx(b.best.lo), p1 = idx(b.best.hi);
  const pick = `<rect class="best" x="${x(p0)}" y="30" width="${(p1 - p0 + 1) * sw}" height="${base - 30}" rx="3"/><text class="pick" x="${x(p0) + ((p1 - p0 + 1) * sw) / 2}" y="${base + 26}">quietest</text>`;
  return `<svg class="chart" viewBox="0 0 360 136" role="img" aria-label="5 GHz networks by channel">${dfs}${out}${pick}<line class="axis" x1="0" y1="${base}" x2="360" y2="${base}"/>${labels}${axis}</svg>`;
}

function bandCard(b, r) {
  const busy = x => (x.count ? `${plural(x.count, "network")} overlap, strongest ${x.strongest} dBm` : "nothing overlapping");
  const what = x => (x.lo === x.hi ? `channel ${x.label}` : `channels ${x.label}`);
  const width = b.band === "5" ? ` at ${b.width} MHz${b.width_assumed ? " (assumed)" : ""}` : "";
  let html = `<div class="band"><h3><span>${b.band} GHz</span><span class="sub">${plural(b.networks, "other network")}</span></h3>`;
  html += `<p>Quietest${width}: <b>${what(b.best)}</b>${b.best.dfs ? " (DFS)" : ""}, ${busy(b.best)}.</p>`;
  if (b.current) {
    const cur = b.band === "5" && b.current.lo !== b.current.hi ? `channel ${b.current.primary} (uses ${b.current.label})` : `channel ${b.current.label}`;
    html += `<p>Yours: ${cur}, ${busy(b.current)}. `;
    if (b.suggest) {
      html += `<b style="color:var(--high)">Action required: Set your router's ${b.band} GHz channel to ${b.best.lo}${b.band === "5" ? ` (width ${b.width} MHz)` : ""} to avoid interference.</b>`;
    } else if (b.current.label === b.best.label) {
      html += `✅ <b style="color:var(--ok)">Already the quietest choice.</b>`;
    } else if (b.current.dfs && !b.best.dfs) {
      html += `About as quiet as ${what(b.best)}, but yours is a DFS channel, so your router pauses for about a minute whenever it detects radar. Channel ${b.best.lo} avoids that.`;
    } else {
      html += "Close to the quietest, no need to change.";
    }
    html += "</p>";
  }
  if (b.width_assumed) html += `<p class="sub">This system doesn't report channel width, so ajar assumes ${b.width} MHz, the usual router default. Check the width in your router's WiFi settings.</p>`;
  if (b.best.dfs) html += `<p class="sub">DFS channels share the air with weather radar. A router on them goes quiet for about a minute when it starts up or detects radar.</p>`;
  return html + chart(b, r.nets) + "</div>";
}

function apDetail(a) {
  const inf = a.info || {};
  const router = [inf.maker, inf.model || inf.model_no, inf.name && inf.name !== inf.model ? inf.name : ""].filter(Boolean).join(" ");
  const facts = [
    ["Access point", a.bssid ? `<span class="mono">${esc(a.bssid)}</span>` : ""],
    ["Maker", a.vendor ? esc(a.vendor) : privateMac(a.bssid) ? "Private address (normal for Wi-Fi Direct, guest networks and hotspots)" : ""],
    ["Router says", esc(router)],
    ["Band", esc(`${a.band} GHz, channel ${a.ch}${a.width ? `, ${a.width} MHz wide` : ""}`)],
    ["Signal", esc(`${a.dbm} dBm (${quality(a.dbm)})`)],
    ["Security", `<span class="sec ${a.sec.grade}">${esc(a.sec.label)}</span>${a.sec.wps ? " WPS on" : ""}`],
    ["Standard", esc([a.gen_label, inf.radio && !a.gen_label.includes(inf.radio) ? inf.radio : ""].filter(Boolean).join(", "))],
    ["Link speed", esc(inf.rate)], ["Connected", a.in_use ? "Yes, this computer" : ""],
  ];
  return `<dl>${facts.filter(f => f[1]).map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>`;
}

function netRow(n) {
  const open = wexp.has(n.key);
  const places = [...new Set(n.aps.map(a => `${a.band} GHz ch ${a.ch}`))].join(", ");
  const chips = (n.mine ? `<span class="tag">Yours</span>` : "") + (n.connected ? `<span class="tag">Connected</span>` : "") +
    (n.kind_label ? `<span class="tag ${n.kind === "backhaul" ? "" : "kind"}">${esc(n.kind_label)}</span>` : "") +
    n.labels.map(l => `<span class="sec ${gradeOf(n, l)}">${esc(l)}</span>`).join("") +
    (n.gen ? `<span class="tag" style="background:var(--ink); color:var(--paper); border-color:var(--ink)">${esc(n.gen)}</span>` : "");
  const about = [n.device ? `Device: <b>${esc(n.device)}</b>` : "", n.related && n.kind !== "backhaul" ? `Same router as ${esc(n.related)}` : ""].filter(Boolean).join(". ");
  return `
    <li class="${n.ssid ? "" : "hidden"}">
      <button class="name" data-act="wtoggle" data-key="${esc(n.key)}" aria-expanded="${open}">${esc(n.ssid || "Hidden network")}</button>
      <span class="meta">${bars(n.dbm)}${n.dbm} dBm, ${esc(places)}${n.aps.length > 1 ? `, ${n.aps.length} access points` : ""}</span>
      ${about ? `<span class="meta">${about}</span>` : ""}
      <span class="chips">${chips}</span>
      <span class="actions">${n.ssid ? `<button class="quiet" data-act="mine" data-ssid="${esc(n.ssid)}" data-on="${n.mine ? 0 : 1}">${n.mine ? "Not mine" : "This is mine"}</button>` : ""}</span>
      ${open ? `<div class="detail">${n.kind_note ? `<p class="about">${esc(n.kind_note)}</p>` : ""}${n.aps.map(apDetail).join("")}</div>` : ""}
    </li>`;
}

function renderWifi(w, now) {
  const r = w.result;
  const pBtn = $("#pingBtn");
  if (pBtn) pBtn.disabled = false;

  const wBtn = $("#wifiBtn");
  if (wBtn) {
    // Disable if WiFi is scanning OR if a network scan is running
    const busy = w.scanning || (data && data.state && data.state.scanning);
    wBtn.disabled = busy;
    wBtn.textContent = w.scanning ? "Scanning…" : "Analyze WiFi";
  }
  $("#wifiSub").textContent = w.scanning ? "Scanning WiFi…" : r && r.scanned ? `${plural(r.nets.length, "network")} in range, scanned ${ago(r.scanned, now)}` : "Not scanned yet. Click Analyze WiFi.";
  $("#wifiBanner").innerHTML = [w.error, r && r.note].filter(Boolean).map(m => `<div class="banner">${esc(m)}</div>`).join("");
  if (!r) {
    $("#conn").textContent = $("#wifiHint").innerHTML = $("#bands").innerHTML = "";
    $("#nets").innerHTML = `<li class="empty">No WiFi scan yet. Tap Scan WiFi.</li>`;
    return;
  }
  const c = r.conn;
  $("#conn").innerHTML = c ? `This computer is connected to <b>${esc(c.ssid || "a hidden network")}</b> on ${c.band} GHz channel ${c.ch}` + `${c.width ? `, ${c.width} MHz` : ""}${c.gen ? ` (${esc(c.gen)})` : ""}. Signal ${c.dbm} dBm (${c.quality})${c.rate ? `, ${esc(c.rate)}` : ""}.` : "This computer isn't connected over WiFi, so this is what its antenna hears from where it sits.";
  const hints = [];
  if (!r.mine_known) hints.push("Tap <b>This is mine</b> on your own network. ajar then checks its security and picks channels for it.");
  const kinds = { direct: ["Wi-Fi Direct device", "Wi-Fi Direct devices"], public: ["public hotspot", "public hotspots"], phone: ["phone hotspot", "phone hotspots"], setup: ["device setup network", "device setup networks"], hidden: ["hidden network", "hidden networks"] };
  const parts = Object.entries(r.around || {}).map(([k, v]) => `${v} ${kinds[k][v === 1 ? 0 : 1]}`);
  if (r.neighbors) hints.push(`Around you: ${plural(r.neighbors, "other network")}` + (parts.length ? `, including ${parts.join(", ")}.` : "."));
  if (r.weak_nearby) hints.push(`${plural(r.weak_nearby, "nearby network")} ${r.weak_nearby === 1 ? "has" : "have"} weak or no security. They aren't yours to fix, but avoid joining them.`);
  const lvl = { high: "High", medium: "Medium", info: "Info" };
  $("#wifiHint").innerHTML = hints.map(h => `<p class="hint">${h}</p>`).join("") +
    (r.findings.length ? `<div class="band"><h3><span>Your WiFi</span></h3><ul class="findings">${r.findings.map(f => `<li><span class="lvl ${f.level}">${lvl[f.level]}</span><b>${esc(f.who)}</b>: ${esc(f.text)}</li>`).join("")}</ul></div>` : r.mine_known ? `<p class="hint">No problems found with your WiFi settings.</p>` : "");
  $("#bands").innerHTML = r.bands.map(b => bandCard(b, r)).join("") + (r.six ? `<div class="band"><h3><span>6 GHz</span><span class="sub">${plural(r.six, "network")}</span></h3>` + `<p>6 GHz is rarely crowded and needs WiFi 6E or 7 on both ends. If your router and devices have it, it's the fastest band at short range.</p></div>` : "");
  $("#nets").innerHTML = r.nets.length ? r.nets.map(netRow).join("") : `<li class="empty">No networks found. Check that WiFi is turned on.</li>`;
}

let settingsDrawn = false;
function renderSettings(force) {
  const box = $("#settings");
  if (data && data.role === "viewer") { box.innerHTML = `<p class="empty">Settings are only available with the main password.</p>`; return; }
  if (!data || !data.alerts) { box.innerHTML = `<p class="empty">Loading…</p>`; return; }
  if (settingsDrawn && !force) return;
  settingsDrawn = true;
  const a = data.alerts, days = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"];
  const lvl = v => `<label><span>Tell me about</span><select data-k="min_level">
    <option value="high"${v==="high"?" selected":""}>Urgent changes only (recommended)</option>
    <option value="medium"${v==="medium"?" selected":""}>Urgent and medium changes</option></select></label>`;
  const allowCreds = Boolean(data.security && data.security.allow_creds);
  const sch = data.schedule || { enabled: false, scan_min: 15, audit_hours: 24 };
  const prefs = data.prefs || { cve_lookup: true };
  const ns = data.net_settings || { segmentation_targets: [], extra_subnets: [] };
  const wh = a.webhook || { enabled: false, url: "", min_level: "high" };
  const withCur = (list, cur) => (list.includes(cur) ? list : [...list, cur].sort((x, y) => x - y));
  const opts = (list, cur, fmt) => withCur(list, cur).map(v => `<option value="${v}"${v === cur ? " selected" : ""}>${fmt(v)}</option>`).join("");
  const mins = v => (v >= 60 ? (v / 60) + (v === 60 ? " hour" : " hours") : v + " minutes");
  const hrs = v => (v >= 48 ? (v / 24) + " days" : v === 168 ? "week" : v + " hours");
  const netBox = !data.network || !data.network.current;
  box.innerHTML = `
    <form class="block" data-api="schedule">
      <label class="switch"><input type="checkbox" data-k="enabled"${sch.enabled ? " checked" : ""}> Scheduled scans</label>
      <p class="intro">Off by default: Ajar only scans when you press a button. Turn this on and it keeps watch by itself, so new devices and changes show up (and alert you) without you opening the page. Leave the computer running.</p>
      <div class="fields"${sch.enabled ? "" : " hidden"}>
        <div class="row">
          <label><span>Quick device sweep every</span><select data-k="scan_min" data-num>${opts([5, 15, 30, 60, 180, 720], sch.scan_min, mins)}</select></label>
          <label><span>Full services check every</span><select data-k="audit_hours" data-num>${opts([6, 12, 24, 72, 168], sch.audit_hours, hrs)}</select></label>
        </div>
      </div>
      <div class="actions"><button type="submit">Save</button><span class="msg"></span></div>
    </form>

    <form class="block" data-api="prefs">
      <label class="switch"><input type="checkbox" data-k="cve_lookup"${prefs.cve_lookup ? " checked" : ""}> Look up known vulnerabilities online</label>
      <p class="intro">To match your devices' software against known security flaws, Ajar sends the software names and versions it found (like "Apache 2.4.49") to vulners.com, and downloads CISA's public list of flaws attackers are exploiting. Nothing else about your network leaves it. Turn this off to keep everything local: results already found are kept, and the score shows this check as "not checked".</p>
      <div class="actions"><button type="submit">Save</button><span class="msg"></span></div>
    </form>

    <form class="block" data-api="netsettings">
      <b>Other networks</b>${netBox ? "" : `<p class="sub">These settings are for the network you're on now.</p>`}
      <p class="intro">Optional. Use one network per line, like 192.168.1.0/24. Only private ranges of up to 256 addresses.</p>
      <label><span>Check that this network is kept apart from these (run Ajar on your guest or smart-home network and list your main one)</span>
        <textarea data-k="segmentation_targets" rows="2" placeholder="192.168.1.0/24">${esc((ns.segmentation_targets || []).join("\n"))}</textarea></label>
      <label><span>Also scan these networks (they must be reachable from here; devices are tracked by IP address)</span>
        <textarea data-k="extra_subnets" rows="2" placeholder="192.168.20.0/24">${esc((ns.extra_subnets || []).join("\n"))}</textarea></label>
      <div class="actions"><button type="submit">Save</button><span class="msg"></span></div>
    </form>

    <form class="block" data-api="viewer">
      <b>View-only access</b>
      <p class="intro">${data.viewer_enabled ? "A view-only password is set." : "Not set."} Share it with someone who should be able to look at the dashboard and reports, but not start scans or change anything. They also can't see your alert settings.</p>
      <label><span>${data.viewer_enabled ? "New view-only password" : "View-only password"} (8 or more characters, different from your main one)</span>
        <input type="password" data-k="password" autocomplete="new-password"></label>
      <div class="actions"><button type="submit">Save</button>${data.viewer_enabled ? '<button type="button" class="quiet" data-viewer-off>Turn off</button>' : ""}<span class="msg"></span></div>
    </form>

    <p class="intro">Alerts are off until you turn one on. Each channel is separate, with its own trigger level.</p>

    <form class="block" data-ch="defaults">
      <label class="switch"><input type="checkbox" id="allowCreds"${allowCreds ? " checked" : ""}> Allow factory-default credential checks</label>
      <p class="intro">Ajar can test a small, curated list of default passwords on devices you explicitly authorize in the device list. Off by default. Every attempt is logged.</p>
    </form>

    <form class="block" data-ch="ntfy">
      <label class="switch"><input type="checkbox" data-k="enabled"${a.ntfy.enabled?" checked":""}> Phone push (ntfy)</label>
      <p class="intro">Free notifications to your phone. Install the ntfy app, pick a hard-to-guess topic name, and subscribe to it.</p>
      <div class="fields"${a.ntfy.enabled?"":" hidden"}>
        <label><span>Server</span><input type="text" data-k="server" value="${esc(a.ntfy.server)}" placeholder="https://ntfy.sh"></label>
        <label><span>Topic (your secret channel name)</span><input type="text" data-k="topic" value="${esc(a.ntfy.topic)}" placeholder="ajar-7f3k9"></label>
        <label><span>Access token (only for a protected topic)</span><input type="password" data-k="token" placeholder="${a.ntfy.has_token?"•••••• (set)":""}"></label>
        ${lvl(a.ntfy.min_level)}
      </div>
      <div class="actions"><button type="submit">Save</button><button type="button" class="quiet" data-test="ntfy">Send test</button><span class="msg"></span></div>
    </form>

    <form class="block" data-ch="email">
      <label class="switch"><input type="checkbox" data-k="enabled"${a.email.enabled?" checked":""}> Email</label>
      <p class="intro">Through your own mail account. Your password is stored only on this device.</p>
      <div class="fields"${a.email.enabled?"":" hidden"}>
        <div class="row">
          <label><span>SMTP server</span><input type="text" data-k="host" value="${esc(a.email.host)}" placeholder="smtp.gmail.com"></label>
          <label style="flex:0 0 6rem"><span>Port</span><input type="number" data-k="port" value="${a.email.port}"></label>
          <label style="flex:0 0 9rem"><span>Security</span><select data-k="security">
            <option value="starttls"${a.email.security==="starttls"?" selected":""}>STARTTLS</option>
            <option value="ssl"${a.email.security==="ssl"?" selected":""}>SSL</option></select></label>
        </div>
        <label><span>Username</span><input type="text" data-k="user" value="${esc(a.email.user)}" placeholder="you@example.com"></label>
        <label><span>Password</span><input type="password" data-k="password" placeholder="${a.email.has_password?"•••••• (set)":"app password"}"></label>
        <label><span>Send alerts to</span><input type="text" data-k="to" value="${esc(a.email.to)}" placeholder="you@example.com"></label>
        ${lvl(a.email.min_level)}
      </div>
      <div class="actions"><button type="submit">Save</button><button type="button" class="quiet" data-test="email">Send test</button><span class="msg"></span></div>
    </form>

    <form class="block" data-ch="webhook">
      <label class="switch"><input type="checkbox" data-k="enabled"${wh.enabled ? " checked" : ""}> Webhook</label>
      <p class="intro">Sends each alert as a JSON message to a web address you choose (Home Assistant, n8n, Node-RED, your own script). If you set a secret, every message is signed so your receiver can check it came from Ajar (header X-Ajar-Signature, HMAC-SHA256).</p>
      <div class="fields"${wh.enabled ? "" : " hidden"}>
        <label><span>URL</span><input type="text" data-k="url" value="${esc(wh.url || "")}" placeholder="https://homeassistant.local/api/webhook/ajar"></label>
        <label><span>Secret (optional)</span><input type="password" data-k="secret" placeholder="${wh.has_secret ? "•••••• (set)" : ""}"></label>
        ${lvl(wh.min_level || "high")}
      </div>
      <div class="actions"><button type="submit">Save</button><button type="button" class="quiet" data-test="webhook">Send test</button><span class="msg"></span></div>
    </form>

    <form class="block" data-ch="weekly">
      <label class="switch"><input type="checkbox" data-k="enabled"${a.weekly.enabled?" checked":""}> Weekly report</label>
      <p class="intro">A plain-English Sunday summary: your score, new devices, what changed, and the top fixes still open.</p>
      <div class="fields"${a.weekly.enabled?"":" hidden"}>
        <div class="row">
          <label><span>Day</span><select data-k="day">${days.map((d,i)=>`<option value="${i}"${a.weekly.day===i?" selected":""}>${d}</option>`).join("")}</select></label>
          <label style="flex:0 0 7rem"><span>Hour</span><input type="number" data-k="hour" min="0" max="23" value="${a.weekly.hour}"></label>
        </div>
        <label class="switch" style="margin-top:10px"><input type="checkbox" data-k="ntfy"${a.weekly.ntfy?" checked":""}> Send it by phone push</label>
        <label class="switch"><input type="checkbox" data-k="email"${a.weekly.email?" checked":""}> Send it by email</label>
      </div>
      <div class="actions"><button type="submit">Save</button><span class="msg"></span></div>
    </form>`;
}

function collectForm(form) {
  const ch = form.dataset.ch, obj = {};
  form.querySelectorAll("[data-k]").forEach(el => {
    const k = el.dataset.k;
    if (el.type === "checkbox") obj[k] = el.checked;
    else if (el.type === "number") obj[k] = +el.value;
    else if (el.type === "password") { if (el.value) obj[k] = el.value; }
    else obj[k] = el.value;
  });
  return { [ch]: obj };
}

function showTab(t) {
  document.querySelectorAll(".tabs button").forEach(b => b.setAttribute("aria-selected", String(b.dataset.tab === t)));
  $("#devices").hidden = t !== "devices";
  $("#wifi").hidden = t !== "wifi";
  $("#security").hidden = t !== "security";
  $("#changes").hidden = t !== "changes";
  $("#settings").hidden = t !== "settings";
  if (t === "changes") { loadEvents(true); }
  if (t === "settings") renderSettings(false);
  document.body.classList.toggle("on-security", t === "security");
  try { localStorage.setItem("ajar-tab", t); } catch {}
}

function dur(sec) {
  sec = Math.max(0, Math.round(sec));
  if (sec < 60) return sec + " s";
  const m = Math.floor(sec / 60), s = sec % 60;
  return m + " min" + (s && m < 10 ? " " + s + " s" : "");
}

let finishedShown = null;
function renderProgress(st, w) {
  const box = $("#progress");
  
  // 1. WiFi Scan Progress
  if (w && w.scanning) {
    box.hidden = false;
    box.className = "";
    box.innerHTML = `<div class="proghead"><b>Analyzing WiFi...</b></div>
      <div class="bar busy"><span></span></div>
      <p>Looking for nearby networks.</p>`;
    document.title = "(WiFi…) Ajar";
    finishedShown = null;
    return;
  }

  // 2. Network Scan Progress
  if (st.scanning && st.steps) {
    const n = st.steps.length;
    const i = Math.min(st.step || 0, n - 1);
    const p = st.progress;
    const frac = p && p.percent != null ? Math.min(1, p.percent / 100) : 0;
    const overall = Math.round(((i + frac) / n) * 100);
    const what = st.full ? "Deep Scan" : st.deep ? "Standard Scan" : "Map Network";
    
    // Only show remaining time if it's more than 3 seconds (nmap always says 1 sec left but takes 10)
    let detail = [st.phase, p ? `${p.task}${p.percent != null ? " " + Math.round(p.percent) + "%" : ""}` : ""].filter(Boolean).join(", ");
    if (p && p.remaining && p.remaining > 3) detail += `, about ${dur(p.remaining)} left in this step`;

    box.hidden = false;
    box.className = "";
    box.innerHTML = `
      <div style="display:flex; align-items:center; gap:10px; font-size:0.875rem; padding: 2px 0;">
        <b style="white-space:nowrap;">${what}</b>
        <span class="sub" style="white-space:nowrap;">Step ${i + 1}/${n}</span>
        <div class="bar${p && p.percent != null ? "" : " busy"}" style="flex:1; margin:0; height:6px;"><span style="width:${p && p.percent != null ? overall : 30}%"></span></div>
        <span class="sub" style="white-space:nowrap;">${dur(st.now - st.started)}</span>
      </div>
      <div style="display:flex; justify-content:space-between; margin-top:4px; font-size:0.75rem; color:var(--muted);">
        <span>${esc(detail)}</span>
      </div>`;
    document.title = `(${p && p.percent != null ? overall + "%" : "…"}) Ajar`;
    finishedShown = null;
    return;
  }

  // 3. Scan Finished (Persistent Result)
  document.title = "Ajar";
  const f = st.finished;
  if (f && !st.error) {
    if (finishedShown === f.at) return; // Already showing this result
    finishedShown = f.at;
    box.hidden = false;
    box.className = "done";
    const onlineCount = data && data.devices ? data.devices.filter(d => d.online).length : 0;
    const what = f.deep ? "Security Scan" : "Map Network";
    
    let actions = `<button class="quiet" style="margin-top:8px" data-act="devices">View Devices</button>`;
    if (f.deep) {
      actions += ` <button style="margin-top:8px" data-act="security">Review Security Findings</button>`;
    }

    box.innerHTML = `<div class="proghead"><b>${what} finished</b><span class="sub">took ${dur(f.took)}</span></div>
      <p>Found <b>${onlineCount}</b> devices online. Expand them in the list below for details.</p>
      <div style="display:flex; gap:10px; flex-wrap:wrap;">${actions}</div>`;
    box.onclick = e => {  // delegated, because a strict Content-Security-Policy blocks inline onclick
      const act = e.target.closest("[data-act]");
      if (!act) return;
      if (act.dataset.act === "devices") $("#list").scrollIntoView({ behavior: "smooth" });
      else if (act.dataset.act === "security") { showTab("security"); window.scrollTo(0, 0); }
    };
    return;
  }

  box.hidden = true;
}

function renderNetbar(res) {
  const n = res.network || {}, nets = res.networks || [];
  if (!n.id) { $("#netbar").innerHTML = ""; return; }
  const opts = nets.map(x => `<option value="${esc(x.id)}"${x.id === n.id ? " selected" : ""}>${esc(x.name || x.subnet)}${x.id === (res.state.net || "") ? " (here now)" : ""}</option>`).join("");
  $("#netbar").innerHTML = `<span>${n.current ? "On" : "Viewing"}: <b>${esc(n.name || n.subnet)}</b> <span class="sub">${esc(n.subnet || "")}</span></span>
    ${nets.length > 1 ? `<select id="netpick" aria-label="Network">${opts}</select>` : ""}
    <button class="quiet" id="netRename">Rename</button>`;
  const here = nets.find(x => x.id === res.state.net);
  const notice = n.current ? "" : `<div class="viewing">Saved results from <b>${esc(n.name)}</b>, last seen ${when(n.last_seen)}. ${here ? `ajar is on <b>${esc(here.name)}</b> now.` : ""} Scans always check the network ajar is on. <button class="quiet" id="netBack">Back to ${here ? esc(here.name) : "the current network"}</button></div>`;
  $("#banner").insertAdjacentHTML("afterbegin", notice);
  // Removed: Scans are always allowed. Clicking Scan while viewing an old network jumps to the live one.
}

let events = [], eventsFor = null, eventsLatest = -1, presenceShown = false;
const seenKey = net => "ajar-seen-" + net;
function lastSeen(net) { try { return +localStorage.getItem(seenKey(net)) || 0; } catch { return 0; } }
function markSeen(net, id) { try { localStorage.setItem(seenKey(net), String(id)); } catch {} }

async function loadEvents(force) {
  if (!data || !data.network || !data.network.id) return;
  const net = data.network.id;
  if (!force && net === eventsFor && data.events_latest === eventsLatest) return;
  try {
    const r = await (await fetch(`/api/events?net=${enc(net)}&presence=${presenceShown ? 1 : 0}`)).json();
    events = r.events || []; eventsFor = net; eventsLatest = data.events_latest;
    renderTimeline();
  } catch { }
}

function renderTimeline() {
  const net = eventsFor, seen = lastSeen(net);
  const fresh = events.filter(e => e.id > seen && (e.level === "high" || e.level === "medium")).length;
  $("#changesBadge").innerHTML = fresh ? `<span class="badge">${fresh}</span>` : "";
  if ($("#changes").hidden) return;
  const lvl = { high: "High", medium: "Medium", info: "Info", presence: "Device" };
  let out = "", day = "";
  for (const e of events) {
    const d = new Date(e.at * 1000), label = d.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });
    if (label !== day) { out += (day ? "</ul>" : "") + `<h3 class="day">${esc(label)}</h3><ul class="events">`; day = label; }
    out += `<li class="${e.level}${e.id > seen ? " fresh" : ""}"><span class="when">${d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" })}</span>
      <span class="what">${e.level === "high" || e.level === "medium" ? `<span class="lvl ${e.level}">${lvl[e.level]}</span>` : ""}${esc(e.text)}</span></li>`;
  }
  $("#timeline").innerHTML = out ? out + "</ul>" : `<p class="empty">No changes recorded yet. ajar notes what changes from one scan to the next.</p>`;
  if (events.length) markSeen(net, Math.max(...events.map(e => e.id)));
}

const savedView = () => !!(data && data.network && data.network.id && !data.network.current);
let viewNet = null;
const netQ = () => (data && data.network && data.network.id ? "net=" + enc(data.network.id) : "");

async function load(force) {
  if (renaming && !force) return;
  let res;
  // slim=1: the server sends full detail only for the devices that are open, which keeps the
  // 5-second refresh small. Opening a device reloads straight away to get its detail.
  const qs = ["slim=1", ...(viewNet ? ["net=" + enc(viewNet)] : []),
              ...(expanded.size ? ["expand=" + [...expanded].map(enc).join(",")] : [])].join("&");
  try { res = await (await fetch("/api/state?" + qs)).json(); }
  catch { $("#sub").textContent = "Cannot reach Ajar. Check that it is running."; return; }
  try { render(res); renderNetbar(res); loadEvents(false); if (!$("#settings").hidden) renderSettings(false); }
  catch (e) { $("#sub").textContent = "The dashboard hit a display problem: " + e.message + ". Please report it."; console.error(e); }
}
async function post(url) { await fetch(url, { method: "POST", headers: { "X-Ajar": "1" } }); load(true); }

$("#scan").onclick = () => { viewNet = null; showTab("devices"); post("/api/scan"); };
$("#netbar").addEventListener("change", e => {
  if (e.target.id !== "netpick") return;
  viewNet = e.target.value === (data && data.state.net) ? null : e.target.value;
  load(true);
});
$("#netbar").addEventListener("click", async e => {
  if (e.target.id !== "netRename" || !data || !data.network) return;
  const name = prompt("Name for this network:", data.network.name || "");
  if (name && name.trim()) post("/api/rename_net?name=" + enc(name.trim()) + "&" + netQ());
});
$("#banner").addEventListener("click", e => {
  if (e.target.id === "netBack") { viewNet = null; load(true); }
});
$("#presence").onchange = e => { presenceShown = e.target.checked; loadEvents(true); };
$("#security").addEventListener("click", e => {
  if (e.target.dataset.accept) acceptRisk(e.target.dataset.accept);
  if (e.target.dataset.unaccept) undoRisk(e.target.dataset.unaccept);
});
$("#settings").addEventListener("change", e => {
  if (e.target.dataset.k === "enabled") {
    const f = e.target.closest("form").querySelector(".fields");
    if (f) f.hidden = !e.target.checked;
  }
  if (e.target.id === "allowCreds") {
    const checked = e.target.checked;
    if (data && data.security) data.security.allow_creds = checked;
    fetch("/api/settings" + (netQ() ? "?" + netQ() : ""), {
      method: "POST",
      headers: { "X-Ajar": "1", "Content-Type": "application/json" },
      body: JSON.stringify({ allow_default_cred_checks: checked })
    }).then(r => {
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    }).then(() => {
      load(true); // Fetch fresh state to confirm the save
    }).catch((err) => {
      console.error("Failed to save credential setting:", err);
      e.target.checked = !checked;
      if (data && data.security) data.security.allow_creds = !checked;
    });
  }
});
const API_FORMS = { schedule: "/api/schedule", prefs: "/api/prefs", viewer: "/api/viewer",
  netsettings: () => "/api/settings" + (netQ() ? "?" + netQ() : "") };
async function saveApiForm(form, override) {
  const msg = form.querySelector(".msg"), kind = form.dataset.api, body = {};
  form.querySelectorAll("[data-k]").forEach(el => {
    body[el.dataset.k] = el.type === "checkbox" ? el.checked : el.hasAttribute("data-num") ? +el.value : el.value;
  });
  Object.assign(body, override || {});
  msg.className = "msg"; msg.textContent = "Saving…";
  try {
    const url = typeof API_FORMS[kind] === "function" ? API_FORMS[kind]() : API_FORMS[kind];
    const resp = await fetch(url, { method: "POST", headers: { "X-Ajar": "1", "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const r = await resp.json();
    if (!resp.ok || r.error) throw new Error(r.error || "Couldn't save.");
    if (kind === "schedule") data.schedule = r.schedule;
    if (kind === "prefs") { data.prefs = r.prefs; load(true); }
    if (kind === "viewer") { data.viewer_enabled = r.viewer_enabled; settingsDrawn = false; renderSettings(true); return; }
    if (kind === "netsettings") {
      const split = s => String(s || "").split(/[\s,]+/).filter(Boolean);
      const bad = Object.values(r.problems || {}).flat();
      data.net_settings = { segmentation_targets: split(body.segmentation_targets).filter(t => !bad.some(b => b.startsWith(t + ":"))),
                            extra_subnets: split(body.extra_subnets).filter(t => !bad.some(b => b.startsWith(t + ":"))) };
      if (bad.length) { msg.className = "msg bad"; msg.textContent = "Saved, except: " + bad.join("; "); return; }
    }
    msg.className = "msg ok"; msg.textContent = "Saved.";
  } catch (err) { msg.className = "msg bad"; msg.textContent = err.message || "Couldn't reach Ajar."; }
}
$("#settings").addEventListener("submit", async e => {
  e.preventDefault();
  if (e.target.dataset.api) return saveApiForm(e.target);
  const form = e.target, msg = form.querySelector(".msg");
  msg.className = "msg"; msg.textContent = "Saving…";
  try {
    const r = await (await fetch("/api/alerts", { method: "POST", headers: { "X-Ajar": "1", "Content-Type": "application/json" }, body: JSON.stringify(collectForm(form)) })).json();
    if (r.ok) { data.alerts = r.alerts; msg.className = "msg ok"; msg.textContent = "Saved."; }
    else { msg.className = "msg bad"; msg.textContent = "Couldn't save."; }
  } catch { msg.className = "msg bad"; msg.textContent = "Couldn't reach Ajar."; }
});
$("#settings").addEventListener("click", async e => {
  if (e.target.hasAttribute("data-viewer-off")) return saveApiForm(e.target.closest("form"), { password: "" });
  const ch = e.target.dataset.test;
  if (!ch) return;
  const form = e.target.closest("form"), msg = form.querySelector(".msg");
  msg.className = "msg"; msg.textContent = "Saving and sending…";
  await fetch("/api/alerts", { method: "POST", headers: { "X-Ajar": "1", "Content-Type": "application/json" }, body: JSON.stringify(collectForm(form)) });
  try {
    const r = await (await fetch("/api/alert_test?channel=" + ch, { method: "POST", headers: { "X-Ajar": "1" } })).json();
    msg.className = "msg " + (r.ok ? "ok" : "bad"); msg.textContent = r.message;
  } catch { msg.className = "msg bad"; msg.textContent = "Couldn't reach Ajar."; }
});
$("#audit").onclick = () => { viewNet = null; showTab("devices"); post("/api/audit"); };
$("#stopScan").onclick = async () => {
  await fetch("/api/stop", { method: "POST", headers: { "X-Ajar": "1" } });
  setTimeout(() => load(true), 300);
};
$("#fullAudit").onclick = () => { viewNet = null; showTab("devices"); post("/api/audit?full=1"); };
$("#approveAll").onclick = () => post("/api/approve?mac=all&" + netQ());
$("#list").onclick = e => {
  const b = e.target.closest("button");
  if (!b) return;
  if (b.dataset.accept) return acceptRisk(b.dataset.accept);
  if (b.dataset.unaccept) return undoRisk(b.dataset.unaccept);
  const mac = b.dataset.mac;
  if (b.dataset.act === "toggle") {
    expanded.has(mac) ? expanded.delete(mac) : expanded.add(mac);
    render(data);
    if (expanded.has(mac)) load(true);  // fetch this device's full detail now, not at the next refresh
  }
  if (b.dataset.act === "approve") post("/api/approve?mac=" + enc(mac) + "&" + netQ());
  if (b.dataset.act === "rename") { renaming = mac; render(data); }
  if (b.dataset.act === "cancel") { renaming = null; render(data); }
  if (b.dataset.act === "auth_cred") {
    fetch("/api/settings" + (netQ() ? "?" + netQ() : ""), {
      method: "POST",
      headers: { "X-Ajar": "1", "Content-Type": "application/json" },
      body: JSON.stringify({ cred_toggle: mac })
    }).then(r => r.json()).then(res => {
      if (res.ok) {
         // Instantly refresh the local data object so the button flips to "Revoke Authorization"
         // without waiting for the 5-second poll.
         load(true);
      }
    });
  }
};
document.querySelector(".tabs").onclick = e => {
  const b = e.target.closest("button[data-tab]");
  if (b) showTab(b.dataset.tab);
};
$("#wifiBtn").onclick = () => { showTab("wifi"); post("/api/wifi"); };
$("#nets").onclick = e => {
  const b = e.target.closest("button");
  if (!b) return;
  if (b.dataset.act === "wtoggle") {
    const k = b.dataset.key;
    wexp.has(k) ? wexp.delete(k) : wexp.add(k);
    render(data);
  }
  if (b.dataset.act === "mine") post("/api/mynet?ssid=" + enc(b.dataset.ssid) + "&mine=" + b.dataset.on + "&" + netQ());
};
$("#scorecard").onclick = e => {
  const b = e.target.closest("button[data-tab]");
  if (b) { showTab(b.dataset.tab); window.scrollTo(0, 0); }
};
try { const t = localStorage.getItem("ajar-tab"); if (["wifi", "security", "changes", "settings"].includes(t)) showTab(t); } catch {}
$("#list").addEventListener("submit", e => {
  e.preventDefault();
  const mac = e.target.dataset.mac, v = e.target.elements.n.value;
  renaming = null;
  post("/api/rename?mac=" + enc(mac) + "&name=" + enc(v) + "&" + netQ());
});
async function tick() {
  await load();
  const busy = data && (data.state.scanning || (data.wifi && data.wifi.scanning));
  setTimeout(tick, busy ? 2000 : 5000);
}
tick();





// Event listener for the Test Stability button
document.addEventListener("click", async (e) => {
  if (!e.target || e.target.id !== "pingBtn") return;
  
  const btn = e.target;
  const res = document.querySelector("#pingResult");
  if (!res) return;
  
  btn.disabled = true;
  btn.textContent = "Testing…";
  res.style.display = "none";
  
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);
    const resp = await fetch("/api/ping", { signal: controller.signal });
    clearTimeout(timeoutId);
    const r = await resp.json();
    
    res.style.display = "block";
    res.style.borderLeftColor = "var(--ok)";
    
    if (r.error) {
      res.style.borderLeftColor = "var(--high)";
      res.innerHTML = `<b style="color:var(--high)">Error:</b> ${esc(r.error)}`;
    } else if (r.loss > 0) {
      res.style.borderLeftColor = "var(--high)";
      res.innerHTML = `<b style="color:var(--high)">Critical: Packet Loss (${r.loss}/${r.sent || 20}).</b> You are dropping connection. <b>Fix:</b> Move closer to the router.`;
    } else if (r.jitter > 30) {
      res.style.borderLeftColor = "var(--med)";
      res.innerHTML = `⚠️ <b>High Jitter (${r.jitter}ms).</b> Unstable connection. <b>Fix:</b> Change your router's channel.`;
    } else if (r.jitter > 10) {
      res.style.borderLeftColor = "var(--med)";
      res.innerHTML = `🟡 <b>Fair (${r.avg}ms, ${r.jitter}ms jitter).</b> Good enough for YouTube, but might stutter.`;
    } else {
      res.innerHTML = `✅ <b>Excellent (${r.avg}ms, ${r.jitter}ms jitter).</b> Rock solid.`;
    }
  } catch (err) {
    res.style.display = "block";
    res.style.borderLeftColor = "var(--high)";
    res.innerHTML = `<b style="color:var(--high)">Failed to reach Ajar.</b>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Test Stability";
  }
});
