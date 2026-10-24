/* FoxyVPN Windows — UI logic. Mirrors the Android app's screens and text. */
'use strict';

/* ---------- Persian helpers (ports of FaFormat.kt / ByteFormat.kt) ---------- */
const JALALI_MONTHS = ["فروردین","اردیبهشت","خرداد","تیر","مرداد","شهریور","مهر","آبان","آذر","دی","بهمن","اسفند"];

function faDigits(n) {
  const s = String(n);
  let out = '';
  for (const ch of s) {
    out += (ch >= '0' && ch <= '9') ? String.fromCharCode(0x06F0 + (ch.charCodeAt(0) - 48)) : ch;
  }
  return out;
}

function toJalali(gy, gm, gd) {
  const gDaysInMonth = [0,31,59,90,120,151,181,212,243,273,304,334];
  let jy = (gy <= 1600) ? 0 : 979;
  const gy2 = (gy <= 1600) ? gy - 621 : gy - 1600;
  const gy3 = (gm > 2) ? gy2 + 1 : gy2;
  let days = 365*gy2 + Math.floor((gy3+3)/4) - Math.floor((gy3+99)/100) + Math.floor((gy3+399)/400)
           - 80 + gDaysInMonth[gm-1] + gd;
  jy += 33 * Math.floor(days/12053);
  days %= 12053;
  jy += 4 * Math.floor(days/1461);
  days %= 1461;
  if (days > 365) {
    jy += Math.floor((days-1)/365);
    days = (days-1) % 365;
  }
  const jm = (days < 186) ? 1 + Math.floor(days/31) : 7 + Math.floor((days-186)/30);
  const jd = (days < 186) ? 1 + (days % 31) : 1 + ((days-186) % 30);
  return [jy, jm, jd];
}

function formatJalaliDate(epochSeconds) {
  try {
    const d = new Date(epochSeconds * 1000);
    const [jy, jm, jd] = toJalali(d.getFullYear(), d.getMonth()+1, d.getDate());
    return `${faDigits(jd)} ${JALALI_MONTHS[jm-1]} ${faDigits(jy)}`;
  } catch (e) { return ''; }
}

function remainingLabel(expiresAtSec, nowMs) {
  const remainingMs = expiresAtSec * 1000 - nowMs;
  if (remainingMs <= 0) return 'اعتبار تمام شده';
  const totalMinutes = Math.floor(remainingMs / 60000);
  const days = Math.floor(totalMinutes / (60*24));
  const hours = Math.floor((totalMinutes % (60*24)) / 60);
  const minutes = totalMinutes % 60;
  if (days >= 1) return `${faDigits(days)} روز`;
  if (hours >= 1) return `${faDigits(hours)} ساعت`;
  return `${faDigits(Math.max(1, minutes))} دقیقه`;
}

function quotaResetLabel(resetAtSec, nowMs) {
  const remainingMs = resetAtSec * 1000 - nowMs;
  if (remainingMs <= 0) return 'حجم ماهانه تازه شد ✓';
  const days = Math.ceil(remainingMs / 86400000);
  return `${faDigits(days)} روز تا شارژ دوبارهٔ حجم`;
}

/* decimal bytes: 1 GB = 1e9 */
const UNITS = ['KB','MB','GB','TB','PB'];
function formatBytes(bytes) {
  if (bytes < 0) return '—';
  if (bytes < 1000) return `${bytes} B`;
  let value = bytes / 1000, index = 0;
  while (value >= 1000 && index < UNITS.length-1) { value /= 1000; index++; }
  const txt = value >= 100 ? value.toFixed(0) : value.toFixed(1);
  return `${txt} ${UNITS[index]}`;
}

function formatDuration(seconds) {
  const h = Math.floor(seconds/3600), m = Math.floor((seconds%3600)/60), s = seconds%60;
  const p = x => String(x).padStart(2, '0');
  return `${p(h)}:${p(m)}:${p(s)}`;
}
function shortDuration(seconds) {
  const h = Math.floor(seconds/3600), m = Math.floor((seconds%3600)/60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

function emojiFlag(code) {
  if (!code || code.length !== 2) return '';
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}

/* ---------- palette (random per open, like FoxyPalettePicker) ---------- */
(function pickPalette() {
  const palettes = [
    { top:'#E7F8EF', bot:'#F4FBF7', accent:'#27C07D', deep:'#128A56' }, // mint
    { top:'#FDE8EC', bot:'#FEF4F6', accent:'#E9486C', deep:'#B72749' }, // rose
    { top:'#E3F0FD', bot:'#F2F8FE', accent:'#2E9BF0', deep:'#1668B4' }, // sky
  ];
  const p = palettes[Math.floor(Math.random() * palettes.length)];
  const r = document.documentElement.style;
  r.setProperty('--grad-top', p.top);
  r.setProperty('--grad-bottom', p.bot);
  r.setProperty('--accent', p.accent);
  r.setProperty('--accent-deep', p.deep);
})();

/* ---------- state ---------- */
const $ = id => document.getElementById(id);
let S = {
  st: null,            // last /api/state snapshot
  screen: 'key',       // key | home | servers | settings
  countries: null,     // server list cache
  selected: { country:'', city:'' },
  pingResults: {},     // "cc:city" -> ms
  pingPending: {},     // "cc:city" -> true
  elapsed: 0,
  connectedAt: null,
  logsOpen: false,
  logsSeq: 0,
  logsHtml: '',
  logTimer: null,
};

async function api(path, opts) {
  const res = await fetch(path, Object.assign({ headers: {'Content-Type':'application/json'} }, opts||{}));
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || ('HTTP ' + res.status));
  return body;
}

/* ---------- screen switching ---------- */
function showScreen(name) {
  S.screen = name;
  for (const s of ['key','home','servers','settings']) {
    $('screen-'+s).hidden = (s !== name);
  }
  if (name === 'servers') loadServers();
  if (name === 'settings') { refreshPortsRow(); if (S.logsOpen) startLogPoll(); else stopLogPoll(); }
  else stopLogPoll();
}

document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => showScreen(btn.dataset.nav));
});
$('serversback').addEventListener('click', () => showScreen('home'));
$('settingsback').addEventListener('click', () => showScreen('home'));

/* ---------- key entry ---------- */
$('keybtn').addEventListener('click', async () => {
  const raw = $('keyinput').value.trim();
  if (!raw) return;
  const btn = $('keybtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';
  $('keyerror').hidden = true;
  try {
    await api('/api/key', { method:'POST', body: JSON.stringify({ key: raw }) });
    $('keyinput').value = '';
    showScreen('home');
  } catch (e) {
    $('keyerror').textContent = e.message;
    $('keyerror').hidden = false;
  }
  btn.disabled = false;
  btn.textContent = 'فعال‌سازی و ورود';
});

/* ---------- power / ping / server card ---------- */
$('power').addEventListener('click', async () => {
  const st = S.st; if (!st) return;
  try {
    if (st.state === 'connected') {
      S.st = await api('/api/disconnect', { method:'POST', body:'{}' });
    } else {
      S.st = await api('/api/connect', { method:'POST', body: JSON.stringify({ country:S.selected.country, city:S.selected.city }) });
    }
    render();
  } catch (e) {
    $('stateerror').textContent = e.message;
    $('stateerror').hidden = false;
  }
});

$('pingpill').addEventListener('click', async () => {
  if (!S.st || S.st.ping_running) return;
  try { S.st = await api('/api/pingall', { method:'POST', body:'{}' }); render(); } catch (e) {}
});

$('servercard').addEventListener('click', () => showScreen('servers'));

/* ---------- settings ---------- */
$('sysproxytoggle').addEventListener('change', async (ev) => {
  try {
    S.st = await api('/api/sysproxy', { method:'POST', body: JSON.stringify({ on: ev.target.checked }) });
  } catch (e) {
    ev.target.checked = !ev.target.checked;
  }
});
$('logsrow').addEventListener('click', () => {
  S.logsOpen = !S.logsOpen;
  $('logbox').hidden = !S.logsOpen;
  if (S.logsOpen) startLogPoll(); else stopLogPoll();
});
$('signout').addEventListener('click', async () => {
  if (!window.confirm('از حساب خارج می‌شوید؟ کلید فعال از این دستگاه حذف می‌شود.')) return;
  try {
    await api('/api/logout', { method:'POST', body:'{}' });
    S.countries = null;
    showScreen('key');
    poll();
  } catch (e) {}
});
function refreshPortsRow() {
  const st = S.st;
  if (st) $('portsrow').textContent = `SOCKS5 127.0.0.1:${st.socks_port} · HTTP 127.0.0.1:${st.http_port}`;
  $('tlssplitrow').textContent = (S.st && S.st.tls_split) ? S.st.tls_split : 'off';
}
function startLogPoll() {
  stopLogPoll();
  const tick = async () => {
    try {
      const r = await api('/api/logs?after=' + S.logsSeq);
      if (r.lines && r.lines.length) {
        const box = $('logbox');
        for (const l of r.lines) {
          const div = document.createElement('div');
          const t = new Date(l.t).toLocaleTimeString('en-GB');
          div.innerHTML = `<span class="lt">${t}</span> <span class="${l.l==='WARN'?'lw':l.l==='ERROR'?'le':''}">[${l.l}]</span> ${escapeHtml(l.m)}`;
          box.appendChild(div);
        }
        S.logsSeq = r.seq;
        box.scrollTop = box.scrollHeight;
      }
    } catch (e) {}
  };
  tick();
  S.logTimer = setInterval(tick, 2000);
}
function stopLogPoll() { if (S.logTimer) { clearInterval(S.logTimer); S.logTimer = null; } }
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

/* ---------- servers screen ---------- */
async function loadServers() {
  try {
    const r = await api('/api/servers');
    S.countries = r.countries;
    S.selected = r.selected || S.selected;
    renderServerList();
  } catch (e) {
    $('serverlist').innerHTML = `<div class="center-note" style="color:var(--error);padding:24px;text-align:center;">${escapeHtml(e.message)}</div>`;
  }
}
function renderServerList() {
  const list = $('serverlist');
  const cs = S.countries || [];
  if (!cs.length) {
    list.innerHTML = '<div class="center-note"><span class="spinner big"></span></div>';
    return;
  }
  let html = '';
  for (const c of cs) {
    html += `<div class="listitem header"><span class="lead"><span class="flag">${emojiFlag(c.code)||'🏳️'}</span></span>
      <span class="main"><span class="headline semibold">${escapeHtml(c.name)}</span></span></div>`;
    for (const city of c.cities) {
      const key = c.code + ':' + city.code;
      const sel = S.selected.country === c.code && S.selected.city === city.code;
      const ping = S.pingResults[key];
      const pending = S.pingPending[key];
      const pingTxt = ping != null ? `${ping} ms` : (pending ? 'pinging…' : 'ping unavailable');
      const host = city.host ? (city.servers > 1 ? `${city.host} (+${city.servers-1} more)` : city.host) : 'No servers available';
      html += `<div class="listitem city" data-cc="${c.code}" data-city="${city.code}">
        <span class="lead"></span>
        <span class="main">
          <span class="headline">${escapeHtml(city.code)}</span>
          <span class="support">${escapeHtml(host)} • ${pingTxt}</span>
        </span>
        <span class="trail">${sel ? CHECK_SVG : ''}</span>
      </div>`;
    }
  }
  list.innerHTML = html;
  list.querySelectorAll('.listitem.city').forEach(row => {
    row.addEventListener('click', () => chooseServer(row.dataset.cc, row.dataset.city));
    const key = row.dataset.cc + ':' + row.dataset.city;
    if (S.pingResults[key] == null && !S.pingPending[key]) {
      S.pingPending[key] = true;
      api(`/api/ping?cc=${encodeURIComponent(row.dataset.cc)}&city=${encodeURIComponent(row.dataset.city)}`)
        .then(r => { if (r.ms > 0) S.pingResults[key] = r.ms; else delete S.pingResults[key]; })
        .catch(() => {})
        .finally(() => { delete S.pingPending[key]; if (S.screen === 'servers') renderServerList(); });
    }
  });
}
const CHECK_SVG = '<svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>';

async function chooseServer(cc, city) {
  try {
    const res = await fetch('/api/choose', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ country:cc, city:city }) });
    if (res.ok) {
      S.selected = { country:cc, city:city };
    }
  } catch (e) {}
  showScreen('home');
  poll();
}

/* ---------- state polling & home rendering ---------- */
async function poll() {
  try {
    S.st = await api('/api/state');
  } catch (e) { return; }
  if (S.screen === 'key' && S.st.has_key) showScreen('home');
  if (S.screen !== 'key' && !S.st.has_key) { S.screen = 'key'; showScreen('key'); }
  if (S.screen === 'home') renderHome();
  if (S.screen === 'settings') refreshPortsRow();
}

function banner(kind, text, cls) {
  const b = $('blockbanner');
  b.hidden = false;
  b.className = 'banner ' + cls;
  b.textContent = text;
  void kind;
}

function renderHome() {
  const st = S.st; if (!st) return;
  $('homever').textContent = 'v3.0.0';

  /* account card */
  const name = st.key_name || 'کاربر';
  $('accname').textContent = name;
  $('accavatar').textContent = [...name.trim()][0] || 'ک';
  let planTxt = 'اشتراک نامحدود فعال است ✓';
  if (st.plan_gb > 0) planTxt = `اشتراک ${st.plan_gb} گیگابایتی فعال است ✓`;
  else if (st.plan_mb > 0) planTxt = `اشتراک ${st.plan_mb} مگابایتی فعال است ✓`;
  $('accplan').textContent = planTxt;

  const nowMs = Date.now();
  if (st.key_exp > 0) {
    $('accexp').hidden = false;
    const expired = st.key_expired || (st.key_exp * 1000 <= nowMs);
    $('accexp').textContent = expired ? 'اعتبار تمام شده' : (remainingLabel(st.key_exp, nowMs) + ' باقی‌مانده');
    $('accexp').className = 'acc-exp' + (expired ? ' expired' : '');
    $('accuntil').hidden = false;
    $('accuntil').textContent = 'تا ' + formatJalaliDate(st.key_exp);
  } else {
    $('accexp').hidden = true;
    $('accuntil').hidden = true;
  }

  if (st.reset_at > 0) {
    $('accreset').hidden = false;
    $('accreset').textContent = quotaResetLabel(st.reset_at, nowMs);
  } else {
    $('accreset').hidden = true;
  }

  /* block banners (Android BlockBanner) */
  const quotaDone = st.limit_bytes > 0 && st.used_bytes >= st.limit_bytes;
  const quotaSoonMsg = (st.state_msg || '').includes('quota');
  if (st.key_expired) banner('exp', 'مهلت کلید شما به پایان رسیده است — برای کلید جدید با پشتیبان خود تماس بگیرید', 'amber');
  else if (quotaDone || quotaSoonMsg) banner('quota', 'حجم کلید شما تمام شده است — برای کلید جدید با پشتیبان خود تماس بگیرید', 'red');
  else $('blockbanner').hidden = true;

  /* usage bar */
  if (st.limit_bytes > 0) {
    $('accprogress').hidden = false;
    $('accusedonly').hidden = true;
    const frac = Math.min(1, Math.max(0, st.used_bytes / st.limit_bytes));
    $('barfill').style.width = (frac * 100).toFixed(1) + '%';
    $('barlabel').textContent = `${formatBytes(st.used_bytes)} از ${formatBytes(st.limit_bytes)} مصرف شده`;
  } else {
    $('accprogress').hidden = true;
    $('accusedonly').hidden = false;
    $('accusedonly').textContent = `مصرف تاکنون: ${formatBytes(st.used_bytes)}`;
  }

  /* power button + state */
  const p = $('power');
  p.classList.remove('st-connecting','st-connected','st-disconnected');
  let statusTxt;
  if (st.state === 'connected') { p.classList.add('st-connected','on'); statusTxt = 'وصل است ✓'; }
  else if (st.state === 'connecting') { p.classList.add('st-connecting'); statusTxt = 'در حال اتصال…'; }
  else { p.classList.add('st-disconnected'); p.classList.remove('on'); statusTxt = 'قطع است'; }
  $('statetext').textContent = statusTxt;

  if (st.state === 'connected' && st.connected_since) {
    if (!S.connectedAt || S.connectedAt !== st.connected_since) {
      S.connectedAt = st.connected_since;
      S.elapsed = Math.max(0, Math.floor((Date.now() - new Date(st.connected_since).getTime()) / 1000));
    }
    $('statetimer').textContent = formatDuration(S.elapsed);
    $('statdur').textContent = shortDuration(S.elapsed);
  } else {
    S.connectedAt = null; S.elapsed = 0;
    $('statetimer').textContent = '00:00:00';
    $('statdur').textContent = '—';
  }

  const errMsg = (st.state !== 'connecting' && (st.last_error || st.state_msg)) ? (st.last_error || st.state_msg) : '';
  $('stateerror').hidden = !errMsg;
  $('stateerror').textContent = errMsg || '';

  /* ping pill + stats */
  $('pingspin').hidden = !st.ping_running;
  $('pingbolt').style.display = st.ping_running ? 'none' : '';
  $('pinglabel').textContent = st.ping_running ? 'در حال تست پینگ…'
    : (st.ping_best_ms > 0 ? `بهترین پینگ: ${st.ping_best_ms} ms (${st.ping_best_where})` : 'تست پینگ همه');
  $('pingpill').disabled = !!st.ping_running;

  $('statping').textContent = st.ping_running ? '…' : (st.ping_best_ms > 0 ? `${st.ping_best_ms} ms` : '—');

  const sessBytes = st.state === 'connected' ? (st.up_bytes + st.down_bytes) : 0;
  $('statsess').textContent = st.state === 'connected' ? formatBytes(sessBytes) : '0 MB';

  /* server card */
  let flag = '🌍', label = 'خودکار (پیشنهادی)';
  if (st.country) {
    flag = emojiFlag(st.country) || '🌍';
    label = countryName(st.country) || st.country;
  }
  $('srvflag').textContent = flag;
  $('srvname').textContent = label;
  $('srvip').textContent = st.exit_ip || '';
  const remain = st.limit_bytes > 0 ? Math.max(0, st.limit_bytes - st.used_bytes) : null;
  if (remain != null) {
    $('srvremain').hidden = false;
    $('srvremain').textContent = `⚡ ${formatBytes(remain)}`;
  } else {
    $('srvremain').hidden = true;
  }
}

function countryName(code) {
  if (S.countries) {
    const c = S.countries.find(x => x.code === code);
    if (c) return c.name;
  }
  return null;
}

/* local 1s ticking for the timer between polls */
setInterval(() => {
  if (S.st && S.st.state === 'connected' && S.connectedAt) {
    S.elapsed += 1;
    $('statetimer').textContent = formatDuration(S.elapsed);
    $('statdur').textContent = shortDuration(S.elapsed);
  }
}, 1000);

setInterval(poll, 1000);
poll();
