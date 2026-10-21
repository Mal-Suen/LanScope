"use strict";

/* LanScope 控制台逻辑：轮询状态、渲染设备/事件/设置、详情抽屉、时间线、通知。 */

const $ = (s) => document.querySelector(s);

const TYPE_LABELS = {
  router: "路由器", pc: "电脑", phone: "手机", tv: "电视/盒子",
  console: "游戏机", nas: "存储", printer: "打印机",
  camera: "摄像头", iot: "智能设备", unknown: "未知",
};
const TYPE_ORDER = ["router", "pc", "phone", "tv", "console", "nas", "printer", "camera", "iot", "unknown"];

const TYPE_ICONS = {
  router: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h.01M10 16.5h.01"/><path d="M7.5 13V7M16.5 13V7"/><circle cx="7.5" cy="5" r="1.3"/><circle cx="16.5" cy="5" r="1.3"/></svg>',
  pc: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="12.5" rx="2"/><path d="M9 20.5h6M12 16.5v4"/></svg>',
  phone: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18.5h2"/></svg>',
  tv: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="2.5" y="4" width="19" height="13" rx="2"/><path d="M9 21h6M12 17v4"/></svg>',
  console: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="2.5" y="7" width="19" height="10" rx="5"/><path d="M7.5 10v3.5M5.75 11.75h3.5"/><circle cx="15.5" cy="11" r="0.9" fill="currentColor" stroke="none"/><circle cx="18" cy="13" r="0.9" fill="currentColor" stroke="none"/></svg>',
  nas: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="3.5" width="16" height="7" rx="1.5"/><rect x="4" y="13.5" width="16" height="7" rx="1.5"/><path d="M7.5 7h.01M7.5 17h.01M17 7h.01M17 17h.01"/></svg>',
  printer: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M6.5 9V3.5h11V9"/><rect x="3" y="9" width="18" height="8" rx="2"/><rect x="7" y="14" width="10" height="6.5" rx="1"/><path d="M17.5 12h.01"/></svg>',
  camera: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="2.5" y="7" width="19" height="13" rx="2"/><circle cx="12" cy="13.5" r="4"/><circle cx="12" cy="13.5" r="1" fill="currentColor" stroke="none"/><path d="M7 7l1.5-2.5h7L17 7"/></svg>',
  iot: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="7" y="7" width="10" height="10" rx="2"/><path d="M10 7V4M14 7V4M10 20v-3M14 20v-3M7 10H4M7 14H4M20 10h-3M20 14h-3"/></svg>',
  unknown: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M9.6 9.5a2.4 2.4 0 1 1 3.4 2.2c-.8.4-1 .9-1 1.8"/><path d="M12 17h.01"/></svg>',
};

const EVENT_TYPE_LABELS = {
  new_device: "新设备", device_online: "上线", device_offline: "离线",
  ip_change: "IP 变更", port_change: "端口变更",
  gateway_change: "网关变更", arp_conflict: "ARP 冲突",
};

let state = null;
let currentTab = "devices";
let drawerMac = null;
let drawerData = null;
let lastEventId = 0;
let polling = false;
let eventFilter = "all";
let reconReport = null;
let reconPolling = false;

/* ---------- 工具 ---------- */

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function setHtml(el, html) {
  if (el._html !== html) {
    el.innerHTML = html;
    el._html = html;
    return true;
  }
  return false;
}

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString("zh-CN", { hour12: false });
}

function fmtDateTime(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString("zh-CN", { hour12: false });
}

function fmtAgo(ts) {
  if (!ts) return "—";
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return s + " 秒前";
  if (s < 3600) return Math.floor(s / 60) + " 分钟前";
  if (s < 86400) return Math.floor(s / 3600) + " 小时前";
  return Math.floor(s / 86400) + " 天前";
}

function displayName(d) {
  return d.custom_name || d.hostname || d.vendor || d.mac.slice(0, 11);
}

function typeOf(d) {
  return d.type || "unknown";
}

async function api(path, method, body) {
  const res = await fetch(path, {
    method: method || "POST",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  return res.json().catch(() => ({}));
}

function toast(message, severity) {
  const el = document.createElement("div");
  el.className = "toast toast-" + (severity || "info");
  el.textContent = message;
  $("#toasts").appendChild(el);
  requestAnimationFrame(() => el.classList.add("show"));
  setTimeout(() => {
    el.classList.remove("show");
    setTimeout(() => el.remove(), 350);
  }, 8000);
}

/* ---------- 轮询 ---------- */

async function refresh() {
  if (polling || document.hidden) return;
  polling = true;
  try {
    const res = await fetch("/api/state", { cache: "no-store" });
    if (!res.ok) return;
    state = await res.json();
    render();
    handleNewToasts();
  } catch (e) {
    /* 服务暂不可达，静默等待下一轮 */
  } finally {
    polling = false;
  }
}

function handleNewToasts() {
  const events = state.events || [];
  const maxId = events.length ? events[0].id : 0;
  if (lastEventId === 0) {
    lastEventId = maxId;
    return;
  }
  for (const ev of events) {
    if (ev.id > lastEventId && (ev.severity === "warn" || ev.severity === "critical")) {
      toast(ev.message, ev.severity);
    }
  }
  lastEventId = Math.max(lastEventId, maxId);
}

/* ---------- 渲染 ---------- */

function render() {
  if (!state) return;
  renderNetInfo();
  renderStats();
  renderDevices();
  renderEvents();
  renderSettings();

  const btn = $("#btnScan");
  btn.disabled = !!state.scan.running;
  btn.textContent = state.scan.running ? "扫描中…" : "立即扫描";

  const unread = state.stats.unread || 0;
  const badge = $("#eventBadge");
  badge.classList.toggle("hidden", unread === 0);
  badge.textContent = unread > 99 ? "99+" : String(unread);
}

function renderNetInfo() {
  const n = state.network;
  setHtml($("#netInfo"),
    `<span title="网卡 ${esc(n.adapter)}">${esc(n.adapter)}</span>` +
    `<span>本机 <b>${esc(n.ip)}</b></span>` +
    `<span>网段 <b>${esc(n.cidr)}</b></span>` +
    `<span>网关 <b>${esc(n.gateway || "未知")}</b></span>`);
}

function renderStats() {
  const s = state.stats;
  const cards = [
    { label: "在线设备", value: s.online, cls: "ok" },
    { label: "已录入", value: s.total, cls: "" },
    { label: "未标记已知", value: s.unknown, cls: s.unknown ? "warn" : "" },
    { label: "未读事件", value: s.unread, cls: s.unread ? "danger" : "" },
  ];
  setHtml($("#statsRow"), cards.map((c) =>
    `<div class="stat-card"><div class="stat-value ${c.cls}">${c.value}</div>` +
    `<div class="stat-label">${c.label}</div></div>`).join(""));

  const scan = state.scan;
  let txt = "";
  if (scan.running) {
    txt = "正在扫描全网段…";
  } else if (scan.last) {
    const last = scan.last;
    txt = `上次扫描 ${fmtAgo(last.ts)}｜耗时 ${last.duration} 秒｜在线 ${last.online} 台` +
      `｜方式 ${last.method === "arp" ? "ARP 扫描" : "ping 扫描"}｜下次巡检约 ${Math.max(1, Math.round(scan.interval / 60))} 分钟后`;
  }
  const ss = $("#scanStatus");
  if (ss.textContent !== txt) ss.textContent = txt;

  const banner = $("#unknownBanner");
  if (s.unknown > 0 && s.total > 0) {
    banner.classList.remove("hidden");
    const html = `<span>有 <b>${s.unknown}</b> 台设备尚未标记为已知设备，新设备告警对它们同样生效。` +
      `</span><button id="btnMarkAllInline" class="btn btn-ghost">全部标记为已知</button>`;
    if (setHtml(banner, html)) {
      const b = $("#btnMarkAllInline");
      if (b) b.onclick = markAllKnown;
    }
  } else {
    banner.classList.add("hidden");
  }

  $("#emptyState").classList.toggle("hidden",
    (state.devices.length > 0) || !!scan.running);
}

function cardHtml(d) {
  const t = typeOf(d);
  const icon = TYPE_ICONS[t] || TYPE_ICONS.unknown;
  const ports = (d.ports || []).slice(0, 6)
    .map((p) => `<span class="port-chip">${p}</span>`).join("");
  const star = d.starred
    ? '<svg class="star" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2.5l2.9 6 6.6.9-4.8 4.6 1.2 6.5L12 17.4l-5.9 3.1 1.2-6.5L2.5 9.4l6.6-.9z"/></svg>'
    : "";
  return `<div class="device-card ${d.online ? "" : "offline"}" data-mac="${esc(d.mac)}">` +
    `<div class="dc-head"><div class="type-icon t-${t}">${icon}</div>` +
    `<div class="dc-title"><div class="dc-name">${esc(displayName(d))}${star}</div>` +
    `<div class="dc-ip"><span class="dot ${d.online ? "on" : "off"}"></span>${esc(d.ip || "—")}</div></div>` +
    `${d.known ? "" : '<span class="chip chip-warn">未标记</span>'}</div>` +
    `<div class="dc-meta"><span class="chip t-chip-${t}">${TYPE_LABELS[t] || t}</span>` +
    `<span class="dc-vendor" title="${esc(d.vendor)}">${esc(d.vendor || "未知厂商")}</span></div>` +
    `${ports ? `<div class="dc-ports">${ports}</div>` : ""}</div>`;
}

function renderDevices() {
  setHtml($("#deviceGrid"), state.devices.map(cardHtml).join(""));
}

function eventRowHtml(ev, small) {
  return `<div class="event-row sev-${ev.severity} ${ev.read ? "" : "unread"}">` +
    `<span class="sev-dot"></span>` +
    `<div class="event-main"><div class="event-msg">${esc(ev.message)}</div>` +
    `${small ? "" : `<div class="event-meta">${EVENT_TYPE_LABELS[ev.type] || ev.type}${ev.mac ? " · " + esc(ev.mac) : ""}</div>`}</div>` +
    `<div class="event-time" title="${fmtDateTime(ev.ts)}">${fmtAgo(ev.ts)}</div></div>`;
}

function renderEvents() {
  let events = state.events || [];
  if (eventFilter === "unread") events = events.filter((ev) => !ev.read);
  else if (eventFilter === "alerts") events = events.filter((ev) => ev.severity !== "info");
  const html = events.map((ev) => eventRowHtml(ev, false)).join("");
  setHtml($("#eventList"), html || '<div class="empty-mini">暂无事件</div>');
}

function safeSetInput(input, value) {
  if (document.activeElement === input) return;
  if (input.type === "checkbox") {
    if (!input.matches(":focus")) input.checked = value;
  } else {
    input.value = value;
  }
}

function renderSettings() {
  const s = state.settings;
  safeSetInput($("#sInterval"), s.patrol_interval);
  safeSetInput($("#sPorts"), s.port_scan === "1");
  safeSetInput($("#sSniffer"), s.sniffer === "1");
  safeSetInput($("#sToast"), s.toast_critical === "1");
  safeSetInput($("#sReconAuto"), s.recon_auto === "1");

  const oui = state.oui;
  const src = oui.source === "ieee" ? "IEEE 全量库" : "内置精简库（尚未联网更新）";
  const when = oui.ts ? "｜更新于 " + fmtDateTime(oui.ts) : "";
  setHtml($("#ouiStatus"),
    `当前：${src}｜收录 ${oui.count} 个前缀${when}${oui.fresh ? "" : "｜建议点击更新"}`);

  setHtml($("#aboutInfo"),
    `LanScope v${esc(state.app.version)}（${esc(state.app.name_cn)}）<br>` +
    `网卡：${esc(state.network.adapter)}<br>` +
    `探测引擎：${state.network.scapy ? "scapy ARP 扫描＋被动嗅探" : "ping 扫描（降级模式）"}<br>` +
    `许可证：GPL-3.0`);
}

/* ---------- 详情抽屉 ---------- */

async function openDrawer(mac) {
  drawerMac = mac;
  try {
    const [res, resRecon] = await Promise.all([
      fetch("/api/devices/" + encodeURIComponent(mac)),
      fetch("/api/devices/" + encodeURIComponent(mac) + "/recon"),
    ]);
    const data = await res.json();
    if (data.error) {
      toast(data.error, "warn");
      return;
    }
    drawerData = data;
    const rd = await resRecon.json();
    reconReport = rd.report || null;
  } catch (e) {
    return;
  }
  renderDrawer();
  $("#drawer").classList.add("open");
  $("#drawerMask").classList.remove("hidden");
}

function closeDrawer() {
  $("#drawer").classList.remove("open");
  $("#drawerMask").classList.add("hidden");
  drawerMac = null;
}

function renderDrawer() {
  const d = drawerData.device;
  const t = typeOf(d);
  const icon = $("#drawerIcon");
  icon.className = "type-icon t-" + t;
  icon.innerHTML = TYPE_ICONS[t] || TYPE_ICONS.unknown;
  $("#drawerName").textContent = displayName(d);
  $("#drawerSub").innerHTML =
    `<span class="dot ${d.online ? "on" : "off"}"></span>${d.online ? "在线" : "离线"} · ${esc(d.ip || "")}`;

  const rows = [
    ["MAC 地址", d.mac],
    ["厂商", d.vendor || "未知"],
    ["主机名", d.hostname || "—"],
    ["类型", TYPE_LABELS[t] || t],
    ["首次发现", fmtDateTime(d.first_seen)],
    ["最近在线", `${fmtDateTime(d.last_seen)}（${fmtAgo(d.last_seen)}）`],
  ];
  setHtml($("#drawerInfo"), rows.map(([k, v]) =>
    `<div class="info-row"><span>${k}</span><b>${esc(v)}</b></div>`).join(""));

  $("#fName").value = d.custom_name || "";
  $("#fType").innerHTML = TYPE_ORDER.map((t2) =>
    `<option value="${t2}">${TYPE_LABELS[t2]}</option>`).join("");
  $("#fType").value = d.custom_type || t;
  $("#fNotes").value = d.notes || "";
  $("#fKnown").checked = d.known;
  $("#fStar").checked = d.starred;

  const ports = drawerData.ports || [];
  const services = d.services || {};
  const portsHtml = ports.length === 0
    ? '<div class="empty-mini">未探测到开放端口（或端口扫描已关闭）</div>'
    : ports.map((p) =>
      `<div class="port-row"><span class="port-chip big">${p}</span>` +
      `<span class="port-desc">${esc(services[p] || "")}</span></div>`).join("");
  setHtml($("#drawerPorts"), portsHtml);

  renderTimeline(drawerData.timeline || []);

  const evs = drawerData.events || [];
  setHtml($("#drawerEvents"),
    evs.map((ev) => eventRowHtml(ev, true)).join("") || '<div class="empty-mini">暂无事件</div>');

  renderReconSection();
}

function renderTimeline(presences) {
  const now = Date.now();
  const span = 24 * 3600 * 1000;
  const segs = [];
  let cur = null;
  for (const p of presences) {
    const t = p.ts * 1000;
    if (t < now - span) continue;
    if (cur && t - cur.end <= 15 * 60 * 1000) {
      cur.end = t;
    } else {
      cur = { start: t, end: t };
      segs.push(cur);
    }
  }
  const segHtml = segs.map((s) => {
    const left = ((s.start - (now - span)) / span) * 100;
    const width = Math.max(0.6, ((s.end - s.start + 60 * 1000) / span) * 100);
    return `<div class="tl-seg" style="left:${left.toFixed(2)}%;width:${Math.min(width, 100 - left).toFixed(2)}%"></div>`;
  }).join("");
  setHtml($("#drawerTimeline"),
    `<div class="tl-track">${segHtml || '<div class="tl-empty">近 24 小时无在线记录</div>'}</div>` +
    `<div class="tl-ticks"><span>24h 前</span><span>18h</span><span>12h</span><span>6h</span><span>现在</span></div>`);
}

/* ---------- 深度侦察 ---------- */

const SEV_LABELS = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示" };

function renderReconSection() {
  const btn = $("#btnRecon");
  const running = !!(state && state.recon && state.recon.running);
  btn.disabled = running;
  btn.textContent = running ? "侦察进行中…" : "开始深度侦察（全端口＋指纹＋风险）";
  const st = state && state.recon ? state.recon : null;
  setHtml($("#reconStatus"),
    running && st ? `正在侦察 ${esc(st.mac || "")}：${esc(st.stage || "")}` : "");
  renderReconReport();
  if (running) pollRecon();
}

function renderReconReport() {
  const box = $("#reconReport");
  if (!reconReport) {
    setHtml(box, '<div class="empty-mini">尚未做过深度侦察。全端口扫描约 10～120 秒，期间会向该设备发送探测流量。</div>');
    return;
  }
  const r = reconReport;
  const sevChip = (s) => `<span class="chip sev-chip-${s}">${SEV_LABELS[s] || esc(s)}</span>`;
  const findingsHtml = (r.findings || []).map((f) =>
    `<div class="recon-row">${sevChip(f.severity)}<span class="recon-msg">${esc(f.message)}` +
    `${f.ports && f.ports.length ? `<span class="recon-ports">（端口 ${f.ports.join(",")}）</span>` : ""}</span></div>`
  ).join("");
  const vulnsHtml = (r.vulns || []).map((v) => {
    const where = v.port === 0 ? "设备级" : `端口 ${v.port}`;
    return `<div class="recon-row">${sevChip(v.severity)}<span class="recon-msg"><b>${v.cve ? esc(v.cve) + " " : ""}${esc(v.name)}</b>` +
      `——${where}｜${esc(v.desc)}<div class="recon-evidence">证据：${esc(v.evidence)}</div></span></div>`;
  }).join("");
  const portsShown = (r.ports || []).slice(0, 30).map((p) => {
    let label = String(p.port);
    let extra = p.service || "";
    if (p.product) {
      extra += (extra ? " " : "") + p.product + (p.version ? " " + p.version : "");
    }
    if (extra) label += `(${extra.trim()})`;
    return `<span class="port-chip" title="${esc((p.banner || "") + " " + (p.extrainfo || ""))}">${esc(label)}</span>`;
  }).join("");
  const os = r.os || {};
  const snmp = r.snmp || {};
  const snmpHtml = (snmp.sysDescr || snmp.sysName)
    ? `<div class="recon-sub">SNMP</div><div class="recon-meta">sysName：${esc(snmp.sysName || "—")}｜sysDescr：${esc((snmp.sysDescr || "").slice(0, 100))}</div>`
    : "";
  const engineLabel = r.engine === "nmap" ? "nmap" : "内置探针";
  setHtml(box,
    `<div class="recon-meta">${fmtDateTime(r.ts)}｜耗时 ${r.duration} 秒｜开放 ${r.open_count} 端口｜引擎：${engineLabel}｜OS 猜测：${esc(os.guess || "未知")}` +
    `${os.nmap ? `｜nmap：${esc(os.nmap)}` : ""}` +
    `${r.skipped_ports && r.skipped_ports.length ? `｜跳过 ${r.skipped_ports.join(",")}（本机劫持端口）` : ""}</div>` +
    (findingsHtml ? `<div class="recon-sub">风险发现</div>${findingsHtml}` : "") +
    (vulnsHtml ? `<div class="recon-sub">漏洞签名命中</div>${vulnsHtml}` : "") +
    snmpHtml +
    (portsShown ? `<div class="recon-sub">开放端口</div><div class="dc-ports">${portsShown}</div>` : "") +
    `<div class="recon-kali">Kali 衔接：<code>${esc(r.kali_hint || "")}</code></div>` +
    `<a class="btn btn-ghost recon-export" href="/api/devices/${encodeURIComponent(r.mac)}/recon/export">导出报告 JSON</a>`);
}

async function startRecon() {
  if (!drawerMac) return;
  const r = await api("/api/devices/" + encodeURIComponent(drawerMac) + "/recon");
  if (!r.started) {
    toast(r.reason || "无法启动侦察", "warn");
    return;
  }
  toast("深度侦察已启动（约 10～120 秒）", "info");
  pollRecon();
}

async function pollRecon() {
  if (reconPolling) return;
  reconPolling = true;
  try {
    while (drawerMac) {
      const res = await fetch("/api/recon/status", { cache: "no-store" });
      const st = await res.json();
      const btn = $("#btnRecon");
      btn.disabled = !!st.running;
      btn.textContent = st.running ? "侦察进行中…" : "开始深度侦察（全端口＋指纹＋风险）";
      setHtml($("#reconStatus"),
        st.running ? `正在侦察 ${esc(st.mac || "")}：${esc(st.stage || "")}` : "");
      if (!st.running) break;
      await new Promise((ok) => setTimeout(ok, 2500));
    }
  } catch (e) {
    /* 状态暂不可达，交回主轮询 */
  }
  reconPolling = false;
  if (drawerMac) await refreshReconReport();
}

async function refreshReconReport() {
  if (!drawerMac) return;
  try {
    const res = await fetch("/api/devices/" + encodeURIComponent(drawerMac) + "/recon");
    const data = await res.json();
    reconReport = data.report || null;
  } catch (e) {
    return;
  }
  renderReconReport();
}

/* ---------- 操作 ---------- */

async function triggerScan() {
  const r = await api("/api/scan");
  if (!r.started) {
    toast(r.reason || "扫描进行中", "warn");
  } else {
    toast("已开始扫描", "info");
    refresh();
  }
}

async function markAllKnown() {
  const r = await api("/api/devices/mark-all-known");
  toast(`已标记 ${r.marked} 台设备为已知`, "info");
  refresh();
}

async function markAllRead() {
  await api("/api/events/read-all");
  refresh();
}

async function saveDevice() {
  if (!drawerMac) return;
  const body = {
    custom_name: $("#fName").value.trim(),
    custom_type: $("#fType").value,
    notes: $("#fNotes").value.trim(),
    known: $("#fKnown").checked ? 1 : 0,
    starred: $("#fStar").checked ? 1 : 0,
  };
  await api("/api/devices/" + encodeURIComponent(drawerMac), "PATCH", body);
  toast("已保存", "info");
  refresh();
  openDrawer(drawerMac);
}

async function saveSettings() {
  const body = {
    patrol_interval: Math.max(60, parseInt($("#sInterval").value, 10) || 300),
    port_scan: $("#sPorts").checked ? "1" : "0",
    sniffer: $("#sSniffer").checked ? "1" : "0",
    toast_critical: $("#sToast").checked ? "1" : "0",
    recon_auto: $("#sReconAuto").checked ? "1" : "0",
  };
  await api("/api/settings", "POST", body);
  toast("设置已保存", "info");
  refresh();
}

async function refreshOui() {
  const btn = $("#btnOuiRefresh");
  btn.disabled = true;
  btn.textContent = "更新中…（约 10～30 秒）";
  const r = await api("/api/oui/refresh");
  btn.disabled = false;
  btn.textContent = "立即更新";
  toast(r.ok ? "MAC 厂商库已更新" : "更新失败（网络不通或被拦截）", r.ok ? "info" : "warn");
  refresh();
}

/* ---------- 标签页与初始化 ---------- */

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll(".tab").forEach((b) =>
    b.classList.toggle("active", b.dataset.tab === tab));
  document.querySelectorAll(".tabpane").forEach((p) =>
    p.classList.toggle("active", p.id === "tab-" + tab));
}

function init() {
  document.querySelectorAll(".tab").forEach((b) =>
    b.addEventListener("click", () => switchTab(b.dataset.tab)));
  $("#btnScan").addEventListener("click", triggerScan);
  $("#btnReadAll").addEventListener("click", markAllRead);
  $("#btnSaveSettings").addEventListener("click", saveSettings);
  $("#btnOuiRefresh").addEventListener("click", refreshOui);
  $("#btnMarkAll").addEventListener("click", markAllKnown);
  $("#btnSaveDevice").addEventListener("click", saveDevice);
  $("#btnRecon").addEventListener("click", startRecon);
  $("#btnCloseDrawer").addEventListener("click", closeDrawer);
  $("#drawerMask").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDrawer();
  });
  $("#eventFilter").addEventListener("change", (e) => {
    eventFilter = e.target.value;
    renderEvents();
  });
  $("#deviceGrid").addEventListener("click", (e) => {
    const card = e.target.closest(".device-card");
    if (card) openDrawer(card.dataset.mac);
  });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) refresh();
  });
  setInterval(refresh, 2500);
  refresh();
}

init();
