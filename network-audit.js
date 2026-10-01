/* ==========================================================================
   Network Security Audit panel  -  network-audit.js
   Self-contained module. Injects its own DOM, binds to any element with
   [data-audit-open], and exposes window.NetAudit { open, close, isOpen }.

   DATA SOURCES (per feed, chosen automatically)
     1. Local backend over WebSocket  ->  ws://localhost:8000/ws
     2. Fallback: WebRTC (subnet hint), Network Information API (link info)
        and clearly-labelled sample data. Browsers cannot read ARP tables,
        Wi-Fi scans or RSSI, so those feeds are simulated until a backend
        supplies them.

   BACKEND MESSAGE PROTOCOL (JSON, one object per frame; arrays also accepted)
     {type:'devices',  devices:[{ip,mac,hostname,vendor,type,status}]}
     {type:'device',   ip,mac,hostname,vendor,type,status}
     {type:'scan',     state:'started'|'progress'|'done', progress:0..1, scanned, total, subnet}
     {type:'spectrum', networks:[{ssid,channel,width,rssi,connected}]}
     {type:'rssi',     value:-58}                       (dBm)
     {type:'dns',      domain,qtype,client,category}    (allowed|tracker|telemetry|threat)
     {type:'dns_leak', resolver,doh,leak,leaks:[...]}   (reply to dns_leak_test)
   CLIENT -> BACKEND
     {type:'hello',client:'gifi-audit'}
     {type:'scan',action:'start'|'stop'}
     {type:'dns_leak_test'}

   Optional config: window.NET_AUDIT_CONFIG = { wsUrl, hash }
   ========================================================================== */
(function () {
  'use strict';
  if (window.NetAudit) return;

  var CFG = Object.assign({
    wsUrl: 'ws://localhost:8000/ws',
    hash: '#network-audit',
    rssiWindow: 90,
    maxDns: 250
  }, window.NET_AUDIT_CONFIG || {});

  var reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ------------------------------------------------------------------ util */
  var clamp = function (v, a, b) { return Math.min(b, Math.max(a, v)); };
  var rnd = function (a, b) { return a + Math.random() * (b - a); };
  var rint = function (a, b) { return Math.floor(rnd(a, b + 1)); };
  var pick = function (a) { return a[Math.floor(Math.random() * a.length)]; };
  var pad = function (n) { return String(n).padStart(2, '0'); };
  var clock = function (d) { d = d || new Date(); return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()); };
  var ipNum = function (ip) { return String(ip).split('.').reduce(function (a, b) { return a * 256 + (+b || 0); }, 0); };
  var esc = function (s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  };
  var svgIcon = function (p) {
    return '<svg class="na-i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + p + '</svg>';
  };
  var ICON = {
    search: svgIcon('<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>'),
    play: svgIcon('<path d="M7 5l11 7-11 7z"/>'),
    stop: svgIcon('<rect x="6" y="6" width="12" height="12" rx="1"/>'),
    back: svgIcon('<path d="M19 12H5M11 6l-6 6 6 6"/>'),
    pause: svgIcon('<path d="M8 5v14M16 5v14"/>'),
    clear: svgIcon('<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>'),
    shield: svgIcon('<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>')
  };

  /* ----------------------------------------------------------------- state */
  var S = {
    open: false, built: false,
    ws: null, wsState: 'idle', wsTries: 0, wsTimer: null, liveAt: {}, pending: {},
    devices: new Map(), seen: new Set(), q: '',
    scan: { on: false, pct: 0, scanned: 0, total: 254, subnet: '192.168.1', last: null, auto: false },
    nets: [], rssi: [], hover: null,
    dns: { all: 0, tracker: 0, telemetry: 0, threat: 0, allowed: 0, paused: false, filter: 'all' },
    leak: { busy: false, res: null, ts: null },
    timers: {}
  };
  var LIVE_WINDOW = { devices: 90000, scan: 90000, spectrum: 60000, rssi: 8000, dns: 10000 };
  function isLive(type) {
    return S.wsState === 'open' && S.liveAt[type] && (Date.now() - S.liveAt[type]) < (LIVE_WINDOW[type] || 10000);
  }
  var V, E = {}, lastFocus = null, colors = {};

  /* ------------------------------------------------------------------ view */
  var TEMPLATE =
    '<div class="na-top"><div class="na-wrap">' +
      '<button class="btn line sm btn-ic na-back" type="button" data-na-close>' + ICON.back + '<span>Back</span></button>' +
      '<span class="stamp na-top-title">[ NETWORK SECURITY AUDIT ]</span>' +
      '<span class="na-conn" id="naConn" role="status" aria-live="polite"><i></i><span>Demo data</span></span>' +
    '</div></div>' +
    '<div class="na-wrap na-body">' +
      '<header class="na-hero">' +
        '<div class="row"><span class="stamp">[ AUDIT PANEL ]</span><span class="stamp">B 04</span></div>' +
        '<h2 id="naTitle">Network security audit</h2>' +
        '<p class="na-lede">Inspect the devices on your subnet, the Wi-Fi channels around you, your signal strength and how your DNS queries leave the network.</p>' +
        '<p class="na-native" id="naNative"></p>' +
      '</header>' +

      '<div class="na-grid na-g4">' +
        '<div class="na-card na-m"><span class="stamp">DEVICES ONLINE</span><div class="na-mv" id="sDev">0</div><div class="na-ms" id="sDevS">—</div></div>' +
        '<div class="na-card na-m"><span class="stamp">BEST CHANNEL</span><div class="na-mv" id="sCh">—</div><div class="na-ms" id="sChS">2.4 GHz / 5 GHz</div></div>' +
        '<div class="na-card na-m"><span class="stamp">SIGNAL</span><div class="na-mv" id="sSig">—<small>dBm</small></div><div class="na-ms" id="sSigS">—</div></div>' +
        '<div class="na-card na-m"><span class="stamp">DNS BLOCKED</span><div class="na-mv" id="sDns">0</div><div class="na-ms" id="sDnsS">of 0 queries</div></div>' +
      '</div>' +

      /* 1. devices */
      '<section class="na-card na-grid" style="display:block" aria-labelledby="naH1">' +
        '<div class="na-head"><span class="stamp" id="naH1">[ SUBNET DISCOVERY &amp; ARP ]</span><span class="na-src" data-src="devices">Demo</span></div>' +
        '<div class="na-tools">' +
          '<label class="na-search">' + ICON.search + '<input id="naQ" type="search" placeholder="Filter by IP, vendor or name" autocomplete="off" autocapitalize="off" spellcheck="false" aria-label="Filter devices by IP, vendor or name"></label>' +
          '<button class="btn line sm btn-ic" id="naScan" type="button" aria-pressed="false"></button>' +
        '</div>' +
        '<div class="na-scanbar" id="naScanBar"><div class="na-prog"><i id="naProg"></i></div><div class="na-scanmeta"><span class="na-pulse"></span><span id="naScanMeta">Idle</span></div></div>' +
        '<div class="na-tablewrap"><table class="na-table"><thead><tr>' +
          '<th>IP Address</th><th>MAC Address</th><th>Hostname / Vendor</th><th>Device Type</th><th>Status</th>' +
        '</tr></thead><tbody id="naRows"></tbody></table></div>' +
        '<p class="na-ms mono" id="naCount" style="margin-top:14px;font-size:12px;color:var(--ash)"></p>' +
      '</section>' +

      /* 2. spectrum */
      '<div class="na-grid na-g2">' +
        '<section class="na-card" aria-labelledby="naH24">' +
          '<div class="na-head"><span class="stamp" id="naH24">[ SPECTRUM 2.4 GHZ ]</span><span class="na-src" data-src="spectrum">Demo</span></div>' +
          '<div class="na-chart" id="naC24"></div>' +
          '<div class="na-legend"><span><i style="background:var(--lime)"></i>Low load</span><span><i style="background:var(--na-warn)"></i>Busy</span><span><i style="background:var(--na-bad)"></i>Congested</span><span><i style="border:1px solid var(--pearl)"></i>Network reach</span></div>' +
          '<div class="na-rec" id="naR24"></div>' +
          '<div class="na-stats" id="naS24"></div>' +
        '</section>' +
        '<section class="na-card" aria-labelledby="naH5">' +
          '<div class="na-head"><span class="stamp" id="naH5">[ SPECTRUM 5 GHZ ]</span><span class="na-src" data-src="spectrum">Demo</span></div>' +
          '<div class="na-chart" id="naC5"></div>' +
          '<div class="na-legend"><span><i style="background:var(--lime)"></i>Low load</span><span><i style="background:var(--na-warn)"></i>Busy</span><span><i style="background:var(--na-bad)"></i>Congested</span><span><i style="border:1px dashed var(--slate)"></i>DFS range</span></div>' +
          '<div class="na-rec" id="naR5"></div>' +
          '<div class="na-stats" id="naS5"></div>' +
        '</section>' +
      '</div>' +

      /* 3 + 4. rssi + leak */
      '<div class="na-grid na-g21">' +
        '<section class="na-card" aria-labelledby="naHR">' +
          '<div class="na-head"><span class="stamp" id="naHR">[ RSSI HISTORY ]</span><span class="na-src" data-src="rssi">Demo</span></div>' +
          '<div class="na-read" id="naRead" data-q="good"><span class="na-big" id="naBig">—</span><span class="u">dBm</span><span class="pill" id="naQual">—</span></div>' +
          '<div class="na-canvas"><canvas id="naCv" role="img" aria-label="Line chart of Wi-Fi signal strength in dBm over the last 90 seconds"></canvas></div>' +
          '<div class="na-th" id="naTh">' +
            '<div class="g" data-q="good"><i></i><span>-30 to -67 dBm</span><span>Excellent / Good signal</span></div>' +
            '<div class="f" data-q="fair"><i></i><span>-68 to -79 dBm</span><span>Fair signal</span></div>' +
            '<div class="p" data-q="poor"><i></i><span>-80 dBm or lower</span><span>Weak / Poor signal</span></div>' +
          '</div>' +
          '<div class="na-stats" id="naRS"></div>' +
        '</section>' +
        '<section class="na-card" aria-labelledby="naHL">' +
          '<div class="na-head"><span class="stamp" id="naHL">[ DNS LEAK ASSESSMENT ]</span><span class="na-src" data-src="leak">Idle</span></div>' +
          '<p class="na-desc">Tests whether your domain name queries bypass encrypted DNS options and leak directly to unencrypted ISP resolvers.</p>' +
          '<div class="na-kv">' +
            '<div><span>Configured resolver</span><span id="naRes">Cloudflare (1.1.1.1)</span></div>' +
            '<div><span>DNS-over-HTTPS</span><span><span class="pill" id="naDoh">Active</span></span></div>' +
            '<div><span>Last test</span><span id="naLast">Not run yet</span></div>' +
          '</div>' +
          '<div class="na-banner" id="naBanner" data-s="idle" role="status" aria-live="polite"><strong>Awaiting test</strong><p>Run the leak test to verify your resolver path.</p></div>' +
          '<button class="btn fill btn-ic" id="naLeak" type="button">' + ICON.shield + '<span>Run leak test</span></button>' +
        '</section>' +
      '</div>' +

      /* 5. dns stream */
      '<section class="na-card na-grid" style="display:block" aria-labelledby="naHD">' +
        '<div class="na-head"><span class="stamp" id="naHD">[ DNS QUERY STREAM ]</span><span class="na-src" data-src="dns">Demo</span></div>' +
        '<div class="na-streamhead">' +
          '<div class="na-seg" id="naSeg" role="group" aria-label="Filter DNS queries">' +
            '<button type="button" data-f="all" aria-pressed="true">All<b id="nfAll">0</b></button>' +
            '<button type="button" data-f="trackers" aria-pressed="false">Trackers<b id="nfTr">0</b></button>' +
            '<button type="button" data-f="blocked" aria-pressed="false">Blocked<b id="nfBl">0</b></button>' +
            '<button type="button" data-f="allowed" aria-pressed="false">Allowed<b id="nfAl">0</b></button>' +
          '</div>' +
          '<div class="na-acts">' +
            '<button class="btn line sm btn-ic" id="naPause" type="button">' + ICON.pause + '<span>Pause</span></button>' +
            '<button class="btn line sm btn-ic" id="naClear" type="button">' + ICON.clear + '<span>Clear</span></button>' +
          '</div>' +
        '</div>' +
        '<div class="code" style="padding:0"><div class="na-feed mono" id="naFeed" data-f="all" role="log" aria-live="off" aria-label="Live DNS queries" tabindex="0"></div></div>' +
      '</section>' +
    '</div>';

  function build() {
    if (S.built) return;
    V = document.createElement('div');
    V.className = 'na-view';
    V.id = 'naView';
    V.setAttribute('role', 'dialog');
    V.setAttribute('aria-modal', 'true');
    V.setAttribute('aria-labelledby', 'naTitle');
    V.setAttribute('aria-hidden', 'true');
    V.innerHTML = TEMPLATE;
    document.body.appendChild(V);
    var q = function (s) { return V.querySelector(s); };
    E = {
      conn: q('#naConn'), native: q('#naNative'), q: q('#naQ'), scan: q('#naScan'), prog: q('#naProg'),
      scanBar: q('#naScanBar'), scanMeta: q('#naScanMeta'), rows: q('#naRows'), count: q('#naCount'),
      c24: q('#naC24'), c5: q('#naC5'), r24: q('#naR24'), r5: q('#naR5'), s24: q('#naS24'), s5: q('#naS5'),
      read: q('#naRead'), big: q('#naBig'), qual: q('#naQual'), cv: q('#naCv'), th: q('#naTh'), rs: q('#naRS'),
      res: q('#naRes'), doh: q('#naDoh'), last: q('#naLast'), banner: q('#naBanner'), leak: q('#naLeak'),
      seg: q('#naSeg'), feed: q('#naFeed'), pause: q('#naPause'), clear: q('#naClear'),
      nfAll: q('#nfAll'), nfTr: q('#nfTr'), nfBl: q('#nfBl'), nfAl: q('#nfAl'),
      sDev: q('#sDev'), sDevS: q('#sDevS'), sCh: q('#sCh'), sChS: q('#sChS'), sSig: q('#sSig'), sSigS: q('#sSigS'),
      sDns: q('#sDns'), sDnsS: q('#sDnsS')
    };
    bind();
    S.built = true;
    paintScanButton();
    renderDevices();
  }

  function bind() {
    V.addEventListener('click', function (e) {
      if (e.target.closest('[data-na-close]')) close();
    });
    E.q.addEventListener('input', function () { S.q = E.q.value; renderDevices(); });
    E.scan.addEventListener('click', toggleScan);
    E.leak.addEventListener('click', runLeak);
    E.seg.addEventListener('click', function (e) {
      var b = e.target.closest('button[data-f]'); if (!b) return;
      S.dns.filter = b.dataset.f; E.feed.dataset.f = b.dataset.f;
      E.seg.querySelectorAll('button').forEach(function (x) { x.setAttribute('aria-pressed', x === b ? 'true' : 'false'); });
      E.feed.scrollTop = E.feed.scrollHeight;
    });
    E.pause.addEventListener('click', function () {
      S.dns.paused = !S.dns.paused;
      E.pause.innerHTML = (S.dns.paused ? ICON.play : ICON.pause) + '<span>' + (S.dns.paused ? 'Resume' : 'Pause') + '</span>';
    });
    E.clear.addEventListener('click', function () {
      E.feed.innerHTML = '';
      S.dns.all = S.dns.tracker = S.dns.telemetry = S.dns.threat = S.dns.allowed = 0;
      renderDnsCounts();
    });
    E.cv.addEventListener('pointermove', function (e) {
      var r = E.cv.getBoundingClientRect(), n = S.rssi.length; if (!n) return;
      var ml = 40, mr = 10, pw = r.width - ml - mr, N = CFG.rssiWindow;
      var f = clamp((e.clientX - r.left - ml) / pw, 0, 1);
      var idx = n - 1 - Math.round((1 - f) * (N - 1));
      S.hover = idx >= 0 && idx < n ? idx : null; drawRssi();
    });
    E.cv.addEventListener('pointerleave', function () { S.hover = null; drawRssi(); });
    if (window.ResizeObserver) {
      var ro = new ResizeObserver(function () { if (S.open) layout(); });
      [E.c24, E.c5, E.cv.parentNode].forEach(function (n) { ro.observe(n); });
    }
  }

  /* ---------------------------------------------------------- open / close */
  function open(push) {
    if (S.open) return;
    build();
    S.open = true;
    lastFocus = document.activeElement;
    var cs = getComputedStyle(document.documentElement);
    colors = {
      lime: cs.getPropertyValue('--lime').trim() || '#c5ff4a',
      warn: '#e3c04d', bad: '#ff6b5c',
      graphite: cs.getPropertyValue('--graphite').trim() || '#252525',
      iron: cs.getPropertyValue('--iron').trim() || '#313131',
      ash: cs.getPropertyValue('--ash').trim() || '#7a7a8a',
      bone: cs.getPropertyValue('--bone').trim() || '#e5e5e5',
      chalk: cs.getPropertyValue('--chalk').trim() || '#fff'
    };
    V.setAttribute('aria-hidden', 'false');
    document.documentElement.classList.add('na-lock');
    V.scrollTop = 0;
    requestAnimationFrame(function () {
      V.classList.add('open');
      layout();
      var b = V.querySelector('[data-na-close]'); if (b) b.focus({ preventScroll: true });
    });
    if (push !== false && location.hash !== CFG.hash) {
      try { history.pushState({ na: 1 }, '', CFG.hash); } catch (e) { /* file:// etc. */ }
    }
    startAll();
  }

  function close(fromPop) {
    if (!S.open) return;
    S.open = false;
    V.classList.remove('open');
    V.setAttribute('aria-hidden', 'true');
    document.documentElement.classList.remove('na-lock');
    stopAll();
    if (!fromPop) {
      try {
        if (history.state && history.state.na) history.back();
        else if (location.hash === CFG.hash) history.replaceState(null, '', location.pathname + location.search);
      } catch (e) { /* ignore */ }
    }
    if (lastFocus && lastFocus.focus) { try { lastFocus.focus({ preventScroll: true }); } catch (e) { /* ignore */ } }
  }

  document.addEventListener('click', function (e) {
    var a = e.target.closest('[data-audit-open]');
    if (a) { e.preventDefault(); open(); }
  });
  document.addEventListener('keydown', function (e) {
    if (!S.open) return;
    if (e.key === 'Escape') { close(); return; }
    if (e.key === 'Tab') {
      var f = V.querySelectorAll('button:not([disabled]),input,[tabindex="0"],a[href]');
      if (!f.length) return;
      var first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  });
  window.addEventListener('popstate', function () {
    if (location.hash === CFG.hash) open(false); else close(true);
  });

  /* -------------------------------------------------------- engine control */
  function startAll() {
    Link.connect();
    nativeInfo();
    seedRssi(); seedNets();
    rssiLoop(); netLoop(); dnsLoop(); heartbeat();
    layout(); renderAll();
    detectSubnet().then(function (p) {
      if (p && !S.devices.size) S.scan.subnet = p;
      if (S.open && !S.scan.auto) { S.scan.auto = true; if (!S.scan.on) toggleScan(); }
      paintScanMeta(); renderDevices();
    });
  }
  function stopAll() {
    Object.keys(S.timers).forEach(function (k) { clearTimeout(S.timers[k]); clearInterval(S.timers[k]); });
    S.timers = {};
    if (S.scan.on) { S.scan.on = false; paintScanButton(); paintScanMeta(); }
    Link.close();
  }
  function every(key, fn, ms) { clearInterval(S.timers[key]); S.timers[key] = setInterval(function () { if (S.open) fn(); }, ms); }
  function heartbeat() { every('hb', function () { paintSources(); paintConn(); }, 1000); paintSources(); paintConn(); }

  /* ----------------------------------------------------------- WebSocket */
  var Link = {
    connect: function () {
      if (S.ws || !('WebSocket' in window)) return;
      clearTimeout(S.wsTimer);
      S.wsState = 'connecting'; paintConn();
      var ws;
      try { ws = new WebSocket(CFG.wsUrl); } catch (e) { return Link.fail(); }
      S.ws = ws;
      var guard = setTimeout(function () { if (ws.readyState !== 1) { try { ws.close(); } catch (e) { /* ignore */ } } }, 3500);
      ws.onopen = function () {
        clearTimeout(guard); S.wsState = 'open'; S.wsTries = 0; paintConn();
        Link.send({ type: 'hello', client: 'gifi-audit' });
      };
      ws.onmessage = function (ev) {
        var m; try { m = JSON.parse(ev.data); } catch (e) { return; }
        (Array.isArray(m) ? m : [m]).forEach(Link.handle);
      };
      ws.onclose = function () {
        clearTimeout(guard);
        if (S.ws === ws) { S.ws = null; S.wsState = 'closed'; S.liveAt = {}; S.liveDev = false; paintConn(); paintSources(); Link.fail(); }
      };
      ws.onerror = function () { /* onclose follows */ };
    },
    fail: function () {
      S.wsState = 'closed'; paintConn();
      if (!S.open) return;
      var delay = Math.min(30000, 4000 * Math.pow(2, S.wsTries++));
      S.wsTimer = setTimeout(function () { if (S.open) Link.connect(); }, delay);
    },
    close: function () {
      clearTimeout(S.wsTimer);
      var ws = S.ws; S.ws = null; S.wsState = 'idle'; S.liveAt = {}; S.liveDev = false;
      if (ws) { ws.onclose = null; try { ws.close(); } catch (e) { /* ignore */ } }
      Object.keys(S.pending).forEach(function (k) { S.pending[k](null); });
      S.pending = {};
    },
    send: function (o) { if (S.ws && S.ws.readyState === 1) { try { S.ws.send(JSON.stringify(o)); return true; } catch (e) { /* ignore */ } } return false; },
    request: function (type, reply, ms) {
      return new Promise(function (resolve) {
        if (!Link.send({ type: type })) return resolve(null);
        var t = setTimeout(function () { delete S.pending[reply]; resolve(null); }, ms);
        S.pending[reply] = function (m) { clearTimeout(t); resolve(m); };
      });
    },
    handle: function (m) {
      if (!m || typeof m !== 'object' || !m.type) return;
      S.liveAt[m.type] = Date.now();
      if (S.pending[m.type]) { var cb = S.pending[m.type]; delete S.pending[m.type]; cb(m); }
      switch (m.type) {
        case 'devices': if (!S.liveDev) { S.liveDev = true; S.devices.clear(); S.seen.clear(); } (m.devices || []).forEach(upsertDevice); renderDevices(); break;
        case 'device': upsertDevice(m); renderDevices(); break;
        case 'scan':
          S.liveAt.devices = Date.now();
          if (m.subnet) S.scan.subnet = String(m.subnet).replace(/\.0(\/\d+)?$/, '');
          if (m.state === 'started') { S.scan.on = true; S.scan.pct = 0; }
          if (m.state === 'done') { S.scan.on = false; S.scan.pct = 1; S.scan.last = new Date(); }
          if (typeof m.progress === 'number') S.scan.pct = clamp(m.progress, 0, 1);
          if (m.scanned != null) S.scan.scanned = m.scanned;
          if (m.total != null) S.scan.total = m.total;
          paintScanButton(); paintScanMeta(); break;
        case 'spectrum': S.nets = (m.networks || []).map(normNet).filter(Boolean); renderSpectrum(); break;
        case 'rssi': {
          var v = Number(m.value != null ? m.value : m.dbm);
          if (isFinite(v)) pushRssi(v);
          break;
        }
        case 'dns': addDns(m); break;
        default: break;
      }
    }
  };

  /* -------------------------------------------------------------- devices */
  function normStatus(s) {
    s = String(s || 'online').toLowerCase();
    return /off|down|gone/.test(s) ? 'offline' : /idle|sleep|away/.test(s) ? 'idle' : 'online';
  }
  function upsertDevice(d) {
    if (!d || !d.ip) return;
    var prev = S.devices.get(d.ip) || {};
    S.devices.set(d.ip, {
      ip: d.ip,
      mac: String(d.mac || prev.mac || '—').toUpperCase(),
      hostname: d.hostname || d.name || prev.hostname || '—',
      vendor: d.vendor || d.oui || prev.vendor || 'Unknown vendor',
      type: d.type || d.deviceType || prev.type || 'Unknown',
      status: normStatus(d.status || prev.status)
    });
  }
  function renderDevices() {
    if (!S.built) return;
    var q = S.q.trim().toLowerCase();
    var all = Array.from(S.devices.values());
    var list = all.filter(function (d) {
      return !q || [d.ip, d.mac, d.hostname, d.vendor, d.type].join(' ').toLowerCase().indexOf(q) > -1;
    }).sort(function (a, b) { return ipNum(a.ip) - ipNum(b.ip); });
    var pill = { online: ['', '● Online'], idle: ['mid', '● Idle'], offline: ['no', '○ Offline'] };
    if (!list.length) {
      E.rows.innerHTML = '<tr class="na-empty"><td colspan="5">' + (all.length ? 'No device matches “' + esc(S.q) + '”.' : 'No devices found yet. Start a scan to discover your subnet.') + '</td></tr>';
    } else {
      E.rows.innerHTML = list.map(function (d) {
        var fresh = S.seen.has(d.ip) ? '' : ' class="na-new"';
        var p = pill[d.status];
        return '<tr' + fresh + '>' +
          '<td data-label="IP Address" class="mono">' + esc(d.ip) + '</td>' +
          '<td data-label="MAC Address" class="mono">' + esc(d.mac) + '</td>' +
          '<td data-label="Hostname / Vendor"><div class="na-hv"><span class="na-host">' + esc(d.hostname) + '</span><span class="na-vend">' + esc(d.vendor) + '</span></div></td>' +
          '<td data-label="Device Type">' + esc(d.type) + '</td>' +
          '<td data-label="Status"><span class="pill ' + p[0] + '">' + p[1] + '</span></td></tr>';
      }).join('');
      list.forEach(function (d) { S.seen.add(d.ip); });
    }
    var on = all.filter(function (d) { return d.status === 'online'; }).length;
    E.count.textContent = list.length + ' of ' + all.length + ' devices shown  •  ' + on + ' online';
    E.sDev.innerHTML = on + '<small>/ ' + all.length + '</small>';
    E.sDevS.textContent = S.scan.subnet + '.0/24';
  }

  /* simulated scan (fallback when no backend is supplying devices) */
  var POOL = [
    ['TP-Link Technologies', '50:C7:BF', 'Gateway', 'tplinkwifi.net'],
    ['Apple, Inc.', 'A4:83:E7', 'Phone', 'iPhone-14-Pro'],
    ['Apple, Inc.', 'F0:18:98', 'Laptop', 'MacBook-Air'],
    ['Samsung Electronics', '8C:79:F5', 'Phone', 'Galaxy-S23'],
    ['Intel Corporate', '3C:97:0E', 'Laptop', 'DESKTOP-7QK2M1'],
    ['Sony Interactive Ent.', 'FC:0F:E6', 'Game Console', 'PS5-Living-Room'],
    ['Google LLC', 'F4:F5:D8', 'Streaming', 'Chromecast'],
    ['Amazon Technologies', '74:C2:46', 'Smart Speaker', 'echo-dot-4'],
    ['Espressif Inc.', '24:6F:28', 'IoT', 'esp32-sensor-02'],
    ['Xiaomi Communications', '64:CC:2E', 'IoT', 'roborock-s7'],
    ['HP Inc.', '3C:D9:2B', 'Printer', 'HP-LaserJet-M110'],
    ['Raspberry Pi Trading', 'DC:A6:32', 'SBC', 'raspberrypi'],
    ['LG Electronics', 'A8:23:FE', 'Smart TV', 'LGwebOSTV'],
    ['Huawei Technologies', '48:46:FB', 'Phone', 'HUAWEI-P40']
  ];
  var simDevs = null, simCursor = 0;
  function makeSim() {
    var rest = POOL.slice(1).sort(function () { return Math.random() - .5; }).slice(0, rint(8, 11));
    var used = { 1: 1 };
    simDevs = [POOL[0]].concat(rest).map(function (p, i) {
      var host = 1;
      if (i) { do { host = rint(2, 254); } while (used[host]); used[host] = 1; }
      var b = function () { return pad(rint(0, 255).toString(16).toUpperCase()); };
      return { host: host, vendor: p[0], mac: p[1] + ':' + b() + ':' + b() + ':' + b(), type: p[2], hostname: p[3], status: 'online', found: false };
    });
  }
  function toggleScan() {
    if (S.scan.on) {
      if (isLive('devices')) Link.send({ type: 'scan', action: 'stop' });
      S.scan.on = false; clearInterval(S.timers.scan);
      paintScanButton(); paintScanMeta(); return;
    }
    S.scan.on = true; S.scan.pct = 0; S.scan.scanned = 0;
    if (S.wsState === 'open') Link.send({ type: 'scan', action: 'start' });
    paintScanButton(); paintScanMeta();
    startSimScan();
  }
  function startSimScan() {
    if (!simDevs) makeSim();
    simCursor = 0;
    clearInterval(S.timers.scan);
    S.timers.scan = setInterval(function () {
      if (!S.open || !S.scan.on) { clearInterval(S.timers.scan); return; }
      if (isLive('devices')) { return; } /* backend is driving the scan */
      simCursor = Math.min(254, simCursor + rint(5, 10));
      S.scan.scanned = simCursor; S.scan.pct = simCursor / 254;
      simDevs.forEach(function (d) {
        if (!d.found && d.host <= simCursor) {
          d.found = true;
          upsertDevice({ ip: S.scan.subnet + '.' + d.host, mac: d.mac, hostname: d.hostname, vendor: d.vendor, type: d.type, status: 'online' });
        }
      });
      if (simCursor >= 254) {
        clearInterval(S.timers.scan);
        simDevs.forEach(function (d, i) {
          d.status = i === 0 ? 'online' : (function (r) { return r < .72 ? 'online' : r < .9 ? 'idle' : 'offline'; })(Math.random());
          if (d.found) upsertDevice({ ip: S.scan.subnet + '.' + d.host, mac: d.mac, hostname: d.hostname, vendor: d.vendor, type: d.type, status: d.status });
        });
        S.scan.on = false; S.scan.last = new Date(); paintScanButton();
      }
      paintScanMeta(); renderDevices();
    }, reduce ? 60 : 130);
  }
  function paintScanButton() {
    if (!E.scan) return;
    var on = S.scan.on;
    E.scan.innerHTML = (on ? ICON.stop : ICON.play) + '<span>' + (on ? 'Stop scan' : 'Start scan') + '</span>';
    E.scan.classList.toggle('on', on);
    E.scan.setAttribute('aria-pressed', on ? 'true' : 'false');
  }
  function paintScanMeta() {
    if (!E.scanMeta) return;
    var s = S.scan;
    E.scanBar.classList.toggle('scanning', s.on);
    E.prog.style.width = (s.on ? s.pct * 100 : (s.last ? 100 : 0)) + '%';
    E.scanMeta.textContent = s.on
      ? 'Scanning ' + s.subnet + '.0/24  •  ' + Math.min(s.scanned, s.total) + ' / ' + s.total + ' hosts'
      : (s.last ? 'Last scan ' + clock(s.last) + '  •  ' + s.subnet + '.0/24' : 'Idle');
  }

  /* WebRTC: read the private subnet from ICE candidates when exposed */
  function detectSubnet() {
    return new Promise(function (res) {
      var done = false, pc;
      var fin = function (v) { if (!done) { done = true; try { pc && pc.close(); } catch (e) { /* ignore */ } res(v); } };
      try { pc = new RTCPeerConnection({ iceServers: [] }); } catch (e) { return res(null); }
      pc.createDataChannel('na');
      pc.onicecandidate = function (e) {
        if (!e.candidate) return fin(null);
        var m = /(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}/.exec(e.candidate.candidate);
        if (m && /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(m[1])) fin(m[1]);
      };
      pc.createOffer().then(function (o) { return pc.setLocalDescription(o); }).catch(function () { fin(null); });
      setTimeout(function () { fin(null); }, 1500);
    });
  }

  /* Network Information API: real link info, no RSSI */
  function nativeInfo() {
    var c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    var set = function () {
      if (!E.native) return;
      E.native.textContent = c
        ? 'Browser link  →  ' + [c.effectiveType, c.downlink ? c.downlink + ' Mbps' : '', c.rtt != null ? c.rtt + ' ms RTT' : '', c.saveData ? 'data saver on' : ''].filter(Boolean).join('  •  ')
        : '';
    };
    set();
    if (c && c.addEventListener && !c._na) { c._na = 1; c.addEventListener('change', set); }
  }

  /* ------------------------------------------------------------- spectrum */
  var B24 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
  var B5 = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165];
  var isDfs = function (c) { return c >= 52 && c <= 144; };

  function normNet(n) {
    if (!n || !n.channel) return null;
    var ch = +n.channel;
    return { ssid: n.ssid || 'Hidden', channel: ch, band: ch <= 14 ? '2.4' : '5', width: +n.width || 20, rssi: clamp(+n.rssi || -80, -100, -25), me: !!(n.connected || n.me) };
  }
  function seedNets() {
    if (S.nets.length) return;
    S.nets = [
      ['HomeNet-2G', 6, 20, -48, 1], ['Neighbor_AP', 1, 20, -62], ['Fiber_A1', 1, 20, -70], ['guest-wifi', 11, 20, -74],
      ['DIRECT-roku', 3, 20, -80], ['CafeGuest', 9, 20, -68],
      ['HomeNet-5G', 149, 80, -52, 1], ['Neighbor5', 36, 40, -66], ['Fiber_5', 40, 20, -71], ['Office-AX', 157, 40, -75],
      ['Hotspot-5', 44, 20, -79], ['MeshNode', 100, 80, -69]
    ].map(function (a) { return normNet({ ssid: a[0], channel: a[1], width: a[2], rssi: a[3], connected: !!a[4] }); });
  }
  function netLoop() {
    every('nets', function () {
      if (isLive('spectrum')) return;
      S.nets.forEach(function (n) {
        n.rssi = clamp(n.rssi + rnd(-2.2, 2.2), -92, -38);
        if (!n.me && Math.random() < .05) {
          var set = n.band === '2.4' ? B24 : B5.filter(function (c) { return !isDfs(c) || Math.random() < .3; });
          n.channel = pick(set);
        }
      });
      renderSpectrum();
    }, 2500);
  }
  function span5(n) {
    var c = n.channel, i = c < 100 ? (c - 36) / 4 : c < 149 ? (c - 100) / 4 : (c - 149) / 4;
    if (n.width >= 80) { var s = c - (i % 4) * 4; return [s, s + 4, s + 8, s + 12]; }
    if (n.width >= 40) { var p = i % 2 === 0 ? c + 4 : c - 4; return [Math.min(c, p), Math.max(c, p)]; }
    return [c];
  }
  function model(band) {
    var chans = band === '2.4' ? B24 : B5, nets = S.nets.filter(function (n) { return n.band === band; });
    var util = {}; chans.forEach(function (c) { util[c] = 3; });
    nets.forEach(function (n) {
      var w = clamp((n.rssi + 95) / 55, .05, 1);
      if (band === '2.4') chans.forEach(function (c) { util[c] += w * Math.max(0, 1 - Math.abs(c - n.channel) * .22) * 42; });
      else span5(n).forEach(function (c) { if (util[c] != null) util[c] += w * 55; });
    });
    chans.forEach(function (c) { util[c] = Math.min(100, Math.round(util[c])); });
    var co = 0, adj = 0;
    for (var i = 0; i < nets.length; i++) for (var j = i + 1; j < nets.length; j++) {
      if (band === '2.4') { var d = Math.abs(nets[i].channel - nets[j].channel); if (d === 0) co++; else if (d < 5) adj++; }
      else { var A = span5(nets[i]), B = span5(nets[j]); if (A.some(function (c) { return B.indexOf(c) > -1; })) co++; }
    }
    var cand = band === '2.4' ? [1, 6, 11] : B5.filter(function (c) { return !isDfs(c) && c < 165; });
    var rec = cand.slice().sort(function (a, b) { return util[a] - util[b]; });
    if (band === '5') rec = rec.slice(0, 3);
    var avg = Math.round(cand.reduce(function (a, c) { return a + util[c]; }, 0) / cand.length);
    return { chans: chans, nets: nets, util: util, co: co, adj: adj, rec: rec, avg: avg, cand: cand };
  }
  var lvl = function (u) { return u < 35 ? 'lo' : u < 65 ? 'mid' : 'hi'; };

  function ensureChart(band, host) {
    var W = Math.floor(host.clientWidth); if (W < 120) return null;
    if (host._w === W && host._svg) return host._svg;
    var chans = band === '2.4' ? B24 : B5, n = chans.length;
    var H = Math.round(clamp(W * .55, 210, 280));
    var ml = 34, mr = 6, mt = 16, mb = band === '5' ? 44 : 28, pw = W - ml - mr, ph = H - mt - mb, sw = pw / n;
    var X = function (i) { return ml + sw * (i + .5); }, Y = function (v) { return mt + ph * (1 - v / 100); };
    var step = band === '2.4' ? 1 : (W < 480 ? 3 : W < 760 ? 2 : 1);
    var g = '<defs><clipPath id="naClip' + band.replace('.', '') + '"><rect x="' + ml + '" y="' + (mt - 2) + '" width="' + pw + '" height="' + (ph + 2) + '"/></clipPath></defs>';
    [0, 25, 50, 75, 100].forEach(function (v) {
      g += '<line class="na-grid-l" x1="' + ml + '" x2="' + (W - mr) + '" y1="' + Y(v) + '" y2="' + Y(v) + '"/>';
      if (v % 50 === 0) g += '<text class="na-ax" x="' + (ml - 6) + '" y="' + (Y(v) + 3) + '" text-anchor="end">' + v + '%</text>';
    });
    g += '<g clip-path="url(#naClip' + band.replace('.', '') + ')"><g class="env"></g></g>';
    var bw = sw * (band === '2.4' ? .42 : .56);
    chans.forEach(function (c, i) {
      g += '<rect class="na-bar' + (band === '5' && isDfs(c) ? ' dfs' : '') + '" data-c="' + c + '" x="' + (X(i) - bw / 2) + '" y="' + Y(100) + '" width="' + bw + '" height="' + ph + '" rx="1.5" style="transform:scaleY(.01)"/>';
      if (i % step === 0) g += '<text class="na-ax" data-t="' + c + '" x="' + X(i) + '" y="' + (mt + ph + 15) + '" text-anchor="middle">' + c + '</text>';
    });
    if (band === '5') {
      var a = chans.indexOf(52), b = chans.indexOf(144);
      g += '<line class="na-dfs" x1="' + (X(a) - sw / 2) + '" x2="' + (X(b) + sw / 2) + '" y1="' + (mt + ph + 26) + '" y2="' + (mt + ph + 26) + '"/>';
      if (W > 400) g += '<text class="na-ax" x="' + ((X(a) + X(b)) / 2) + '" y="' + (mt + ph + 38) + '" text-anchor="middle">DFS</text>';
    }
    g += '<g class="marks"></g>';
    host.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" width="' + W + '" height="' + H + '" role="img" aria-label="Channel congestion chart for ' + band + ' GHz">' + g + '</svg>';
    host._w = W; host._svg = host.firstChild; void host._svg.getBoundingClientRect();
    host._geo = { ml: ml, mt: mt, ph: ph, sw: sw, X: X, Y: Y };
    return host._svg;
  }
  function paintChart(band) {
    var host = band === '2.4' ? E.c24 : E.c5, svg = ensureChart(band, host); if (!svg) return;
    var m = model(band), geo = host._geo, chans = m.chans;
    var env = '';
    m.nets.forEach(function (n) {
      var amp = clamp((n.rssi + 95) / 55, .08, 1) * 92, d;
      if (band === '2.4') {
        var ci = n.channel - 1; d = 'M' + geo.X(ci - 2.4) + ',' + geo.Y(0);
        for (var k = -24; k <= 24; k++) { var o = k / 10; d += ' L' + geo.X(ci + o).toFixed(1) + ',' + geo.Y(amp * Math.exp(-o * o / 1.4)).toFixed(1); }
        d += ' L' + geo.X(ci + 2.4) + ',' + geo.Y(0) + 'Z';
      } else {
        var idx = span5(n).map(function (c) { return chans.indexOf(c); }).filter(function (i) { return i > -1; });
        if (!idx.length) return;
        var x0 = geo.X(Math.min.apply(null, idx)) - geo.sw * .5, x1 = geo.X(Math.max.apply(null, idx)) + geo.sw * .5;
        d = 'M' + x0 + ',' + geo.Y(0) + ' L' + (x0 + geo.sw * .14) + ',' + geo.Y(amp) + ' L' + (x1 - geo.sw * .14) + ',' + geo.Y(amp) + ' L' + x1 + ',' + geo.Y(0) + 'Z';
      }
      env += '<path class="na-env' + (n.me ? ' me' : '') + '" d="' + d + '"><title>' + esc(n.ssid) + ' • ch ' + n.channel + ' • ' + Math.round(n.rssi) + ' dBm</title></path>';
    });
    svg.querySelector('.env').innerHTML = env;
    svg.querySelectorAll('.na-bar').forEach(function (r) {
      var c = +r.dataset.c, u = m.util[c];
      r.style.transform = 'scaleY(' + Math.max(.01, u / 100) + ')';
      r.setAttribute('class', 'na-bar ' + lvl(u) + (band === '5' && isDfs(c) ? ' dfs' : ''));
    });
    var marks = '';
    m.rec.slice(0, band === '2.4' ? 3 : 1).forEach(function (c, i) {
      var x = geo.X(chans.indexOf(c)), y = 6, s = i === 0 ? 5 : 3.2;
      marks += '<path class="na-diam" style="opacity:' + (i === 0 ? 1 : .45) + '" d="M' + x + ',' + (y - s) + ' L' + (x + s) + ',' + y + ' L' + x + ',' + (y + s) + ' L' + (x - s) + ',' + y + 'Z"/>';
    });
    svg.querySelector('.marks').innerHTML = marks;
    svg.querySelectorAll('text[data-t]').forEach(function (t) { t.classList.toggle('hl', m.rec[0] === +t.dataset.t); });

    var rec = band === '2.4' ? E.r24 : E.r5, stats = band === '2.4' ? E.s24 : E.s5;
    rec.innerHTML = '<span>Recommended</span>' + m.rec.map(function (c, i) {
      return '<span class="na-chip' + (i === 0 ? ' best' : '') + '">Ch ' + c + '<em>' + m.util[c] + '%</em></span>';
    }).join('') + (band === '5' ? '<span style="flex-basis:100%;font-size:11px">DFS channels excluded</span>' : '');
    var lab = m.avg < 35 ? ['Low', ''] : m.avg < 60 ? ['Moderate', 'warn'] : ['High', 'bad'];
    stats.innerHTML = '<div>Congestion <span class="pill ' + lab[1] + '">' + lab[0] + '</span></div>' +
      '<div>Co-channel <b>' + m.co + '</b></div>' +
      (band === '2.4' ? '<div>Adjacent overlap <b>' + m.adj + '</b></div>' : '') +
      '<div>Networks <b>' + m.nets.length + '</b></div>';
    return m;
  }
  function renderSpectrum() {
    if (!S.built || !S.open) return;
    var a = paintChart('2.4'), b = paintChart('5');
    if (a && b) {
      E.sCh.textContent = 'Ch ' + a.rec[0] + ' / ' + b.rec[0];
      E.sChS.textContent = '2.4 GHz ' + a.util[a.rec[0]] + '%  •  5 GHz ' + b.util[b.rec[0]] + '%';
    }
  }

  /* ----------------------------------------------------------------- RSSI */
  var rssiTarget = -58;
  function seedRssi() {
    if (S.rssi.length) return;
    var v = -58, now = Date.now();
    for (var i = 59; i >= 0; i--) { v = clamp(v + (rssiTarget - v) * .12 + (Math.random() - .5) * 3, -92, -38); S.rssi.push({ t: now - i * 1000, v: Math.round(v * 10) / 10 }); }
  }
  function rssiLoop() {
    every('rssi', function () {
      if (isLive('rssi')) return;
      var last = S.rssi.length ? S.rssi[S.rssi.length - 1].v : -58;
      if (Math.random() < .05) rssiTarget = rnd(-84, -48);
      pushRssi(clamp(last + (rssiTarget - last) * .12 + (Math.random() - .5) * 3.2, -95, -35));
    }, 1000);
  }
  function pushRssi(v) {
    S.rssi.push({ t: Date.now(), v: Math.round(v * 10) / 10 });
    if (S.rssi.length > CFG.rssiWindow) S.rssi.shift();
    if (S.open) renderRssi();
  }
  var qOf = function (v) { v = Math.round(v); return v >= -67 ? 'good' : v >= -79 ? 'fair' : 'poor'; };
  var QL = { good: ['Excellent / Good', ''], fair: ['Fair', 'warn'], poor: ['Weak / Poor', 'bad'] };
  function renderRssi() {
    if (!S.built || !S.rssi.length) return;
    var cur = S.rssi[S.rssi.length - 1].v, q = qOf(cur);
    E.big.textContent = Math.round(cur);
    E.read.dataset.q = q;
    E.qual.textContent = QL[q][0]; E.qual.className = 'pill ' + QL[q][1];
    E.th.querySelectorAll('div').forEach(function (d) { d.classList.toggle('cur', d.dataset.q === q); });
    var vs = S.rssi.map(function (p) { return p.v; });
    var mn = Math.min.apply(null, vs), mx = Math.max.apply(null, vs), av = vs.reduce(function (a, b) { return a + b; }, 0) / vs.length;
    E.rs.innerHTML = '<div>Min <b>' + Math.round(mn) + ' dBm</b></div><div>Avg <b>' + Math.round(av) + ' dBm</b></div><div>Max <b>' + Math.round(mx) + ' dBm</b></div><div>Window <b>' + vs.length + ' s</b></div>';
    E.sSig.innerHTML = Math.round(cur) + '<small>dBm</small>';
    E.sSigS.textContent = QL[q][0];
    drawRssi();
  }
  function drawRssi() {
    var cv = E.cv; if (!cv || !S.open) return;
    var W = Math.floor(cv.parentNode.clientWidth); if (W < 120) return;
    var H = W < 520 ? 220 : 280, dpr = Math.min(window.devicePixelRatio || 1, 2.5);
    if (cv.width !== Math.round(W * dpr) || cv.height !== Math.round(H * dpr)) { cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr); cv.style.height = H + 'px'; }
    var c = cv.getContext('2d'); c.setTransform(dpr, 0, 0, dpr, 0, 0); c.clearRect(0, 0, W, H);
    var ml = 40, mr = 10, mt = 10, mb = 22, pw = W - ml - mr, ph = H - mt - mb, lo = -100, hi = -30, N = CFG.rssiWindow;
    var Y = function (v) { return mt + ph * (hi - v) / (hi - lo); };
    var mono = '10px "JetBrains Mono",ui-monospace,Menlo,monospace';

    [[-30, -67.5, colors.lime], [-67.5, -79.5, colors.warn], [-79.5, -100, colors.bad]].forEach(function (b) {
      c.globalAlpha = .07; c.fillStyle = b[2]; c.fillRect(ml, Y(b[0]), pw, Y(b[1]) - Y(b[0])); c.globalAlpha = 1;
    });
    c.strokeStyle = colors.graphite; c.lineWidth = 1; c.fillStyle = colors.ash; c.font = mono; c.textAlign = 'right';
    [-30, -50, -67, -80, -100].forEach(function (v) {
      var y = Math.round(Y(v)) + .5;
      c.beginPath(); c.moveTo(ml, y); c.lineTo(ml + pw, y); c.stroke();
      c.fillText(v, ml - 6, y + 3);
    });
    c.setLineDash([4, 4]);
    [[-67.5, colors.lime], [-79.5, colors.warn]].forEach(function (t) {
      c.strokeStyle = t[1]; c.globalAlpha = .45; c.beginPath(); c.moveTo(ml, Y(t[0])); c.lineTo(ml + pw, Y(t[0])); c.stroke(); c.globalAlpha = 1;
    });
    c.setLineDash([]);
    c.textAlign = 'center'; c.fillStyle = colors.ash;
    [[0, '-' + N + 's'], [.5, '-' + Math.round(N / 2) + 's'], [1, 'now']].forEach(function (t) {
      c.textAlign = t[0] === 0 ? 'left' : t[0] === 1 ? 'right' : 'center';
      c.fillText(t[1], ml + pw * t[0], H - 6);
    });

    var n = S.rssi.length; if (!n) return;
    var X = function (k) { return ml + pw * (1 - (n - 1 - k) / (N - 1)); };
    var g = c.createLinearGradient(0, Y(hi), 0, Y(lo));
    g.addColorStop(0, colors.lime); g.addColorStop(.50, colors.lime); g.addColorStop(.58, colors.warn); g.addColorStop(.66, colors.warn); g.addColorStop(.74, colors.bad); g.addColorStop(1, colors.bad);
    c.beginPath();
    S.rssi.forEach(function (p, k) { k ? c.lineTo(X(k), Y(p.v)) : c.moveTo(X(k), Y(p.v)); });
    c.lineWidth = 2; c.lineJoin = 'round'; c.strokeStyle = g; c.stroke();

    var li = n - 1, lq = qOf(S.rssi[li].v), lc = lq === 'good' ? colors.lime : lq === 'fair' ? colors.warn : colors.bad;
    c.fillStyle = lc; c.shadowColor = lc; c.shadowBlur = 8; c.beginPath(); c.arc(X(li), Y(S.rssi[li].v), 3.5, 0, 6.283); c.fill(); c.shadowBlur = 0;

    if (S.hover != null && S.rssi[S.hover]) {
      var p = S.rssi[S.hover], hx = X(S.hover), hy = Y(p.v);
      c.strokeStyle = colors.bone; c.globalAlpha = .35; c.beginPath(); c.moveTo(hx, mt); c.lineTo(hx, mt + ph); c.stroke(); c.globalAlpha = 1;
      c.fillStyle = colors.chalk; c.beginPath(); c.arc(hx, hy, 3, 0, 6.283); c.fill();
      var t = Math.round(p.v) + ' dBm  ' + clock(new Date(p.t)), tw = c.measureText(t).width + 16, bx = clamp(hx - tw / 2, ml, ml + pw - tw);
      c.fillStyle = '#000'; c.strokeStyle = colors.iron; c.fillRect(bx, mt + 4, tw, 22); c.strokeRect(bx + .5, mt + 4.5, tw - 1, 21);
      c.fillStyle = colors.chalk; c.textAlign = 'left'; c.fillText(t, bx + 8, mt + 19);
    }
  }

  /* ------------------------------------------------------------- DNS leak */
  function setBanner(state, title, text) {
    E.banner.dataset.s = state;
    E.banner.innerHTML = '<strong>' + esc(title) + '</strong><p>' + esc(text) + '</p>';
  }
  function browserProbe() {
    var name = 'na-' + Math.random().toString(36).slice(2, 10) + '.example.com';
    var targets = [
      ['Cloudflare (1.1.1.1)', 'https://cloudflare-dns.com/dns-query?name=' + name + '&type=A'],
      ['Google Public DNS (8.8.8.8)', 'https://dns.google/resolve?name=' + name + '&type=A']
    ];
    var i = 0;
    var next = function () {
      if (i >= targets.length) return Promise.resolve({ basis: 'browser', error: true });
      var t = targets[i++], t0 = performance.now(), ctl = new AbortController(), to = setTimeout(function () { ctl.abort(); }, 4500);
      return fetch(t[1], { headers: { accept: 'application/dns-json' }, cache: 'no-store', signal: ctl.signal })
        .then(function (r) { clearTimeout(to); if (!r.ok) throw 0; return r.json(); })
        .then(function () { return { basis: 'browser', resolver: t[0], doh: true, leak: false, ms: Math.round(performance.now() - t0) }; })
        .catch(function () { clearTimeout(to); return next(); });
    };
    return next();
  }
  function runLeak() {
    if (S.leak.busy) return;
    S.leak.busy = true;
    E.leak.disabled = true; E.leak.querySelector('span').textContent = 'Testing…';
    setBanner('run', 'Testing resolver path', 'Sending encrypted probe queries…');
    var src = document.querySelector('.na-src[data-src="leak"]'); if (src) { src.textContent = 'Running'; src.classList.remove('live'); }
    var wait = new Promise(function (r) { setTimeout(r, reduce ? 0 : 900); });
    var job = (S.wsState === 'open' ? Link.request('dns_leak_test', 'dns_leak', 7000) : Promise.resolve(null))
      .then(function (m) { return m ? Object.assign({ basis: 'backend' }, m) : browserProbe(); });
    Promise.all([job, wait]).then(function (r) {
      var res = r[0]; S.leak.busy = false; S.leak.res = res; S.leak.ts = new Date();
      E.leak.disabled = false; E.leak.querySelector('span').textContent = 'Run leak test';
      paintLeak(res);
    });
  }
  function paintLeak(r) {
    var src = document.querySelector('.na-src[data-src="leak"]');
    E.last.textContent = clock(S.leak.ts);
    if (r.error) {
      E.res.textContent = 'Unreachable';
      E.doh.textContent = 'Unknown'; E.doh.className = 'pill no';
      setBanner('warn', 'Test unavailable', 'No encrypted resolver could be reached. Check your connection or disable content blockers for this page, then run the test again.');
      if (src) src.textContent = 'Failed';
      return;
    }
    E.res.textContent = r.resolver || 'Cloudflare (1.1.1.1)';
    E.doh.textContent = r.doh === false ? 'Inactive' : 'Active'; E.doh.className = 'pill ' + (r.doh === false ? 'bad' : '');
    if (r.leak) {
      var ips = (r.leaks || []).map(function (l) { return typeof l === 'string' ? l : (l.ip || ''); }).filter(Boolean).join(', ');
      setBanner('bad', 'Leak detected', 'Queries reached an unencrypted resolver' + (ips ? ': ' + ips : '') + '. Enable DNS-over-HTTPS in your device or router.');
    } else if (r.basis === 'backend') {
      setBanner('ok', 'No leaks detected', 'Backend verified every observed query used the encrypted resolver.');
    } else {
      setBanner('ok', 'No leaks detected', 'Browser probe: encrypted resolver reached in ' + r.ms + ' ms. Connect the local backend for resolver-level confirmation.');
    }
    if (src) { src.textContent = r.basis === 'backend' ? 'Live' : 'Browser probe'; src.classList.toggle('live', r.basis === 'backend'); }
  }

  /* ------------------------------------------------------------ DNS stream */
  var DOM = {
    allowed: ['github.com', 'fonts.googleapis.com', 'cdn.jsdelivr.net', 'speed.cloudflare.com', 'wikipedia.org', 'youtube.com', 'spotify.com', 'whatsapp.net', 'icloud.com', 'netflix.com', 'ocsp.digicert.com', 'time.apple.com'],
    tracker: ['doubleclick.net', 'googlesyndication.com', 'connect.facebook.net', 'ads.twitter.com', 'scorecardresearch.com', 'adnxs.com', 'criteo.com', 'taboola.com', 'hotjar.com', 'amplitude.com'],
    telemetry: ['vortex.data.microsoft.com', 'app-measurement.com', 'metrics.icloud.com', 'settings-win.data.microsoft.com', 'analytics.samsung.com', 'ssl.google-analytics.com', 'crashlytics.com'],
    threat: ['a8f3k2.botnet-demo.top', 'login-verify.phish-demo.xyz', 'dl-payload.malware-demo.ru']
  };
  var CAT_LABEL = { allowed: 'Allowed', tracker: 'Tracker', telemetry: 'Telemetry', threat: 'Blocked Threat' };
  function normCat(c) {
    c = String(c || 'allowed').toLowerCase();
    return /threat|malware|phish|block|malic/.test(c) ? 'threat' : /telemetry|diagnos/.test(c) ? 'telemetry' : /track|\bads?\b|advert/.test(c) ? 'tracker' : 'allowed';
  }
  function dnsLoop() {
    var tick = function () {
      if (!S.open) return;
      if (!isLive('dns') && !S.dns.paused) {
        for (var i = rint(1, 2); i > 0; i--) {
          var r = Math.random(), cat = r < .56 ? 'allowed' : r < .76 ? 'tracker' : r < .94 ? 'telemetry' : 'threat';
          addDns({ domain: pick(DOM[cat]), qtype: pick(['A', 'A', 'AAAA', 'HTTPS']), client: S.scan.subnet + '.' + rint(2, 60), category: cat, sim: 1 });
        }
      }
      S.timers.dnsT = setTimeout(tick, reduce ? 1400 : rint(350, 1100));
    };
    clearTimeout(S.timers.dnsT); tick();
  }
  function addDns(m) {
    if (S.dns.paused && !m.sim) return;
    var cat = normCat(m.category || m.cat), d = S.dns;
    d.all++; d[cat]++;
    var near = E.feed.scrollHeight - E.feed.scrollTop - E.feed.clientHeight < 40;
    var row = document.createElement('div');
    row.className = 'na-q' + (reduce ? '' : ' in'); row.dataset.c = cat;
    row.innerHTML = '<time>' + clock() + '</time><span class="na-badge">' + CAT_LABEL[cat] + '</span><span class="dom">' + esc(m.domain || m.name || '?') + '</span><span class="meta">' + esc(m.qtype || 'A') + (m.client ? '  ' + esc(m.client) : '') + '</span>';
    E.feed.appendChild(row);
    while (E.feed.children.length > CFG.maxDns) E.feed.removeChild(E.feed.firstChild);
    if (near) E.feed.scrollTop = E.feed.scrollHeight;
    renderDnsCounts();
  }
  function renderDnsCounts() {
    var d = S.dns;
    E.nfAll.textContent = d.all; E.nfTr.textContent = d.tracker + d.telemetry; E.nfBl.textContent = d.threat; E.nfAl.textContent = d.allowed;
    E.sDns.textContent = d.threat; E.sDnsS.textContent = 'of ' + d.all + ' queries';
  }

  /* ------------------------------------------------------ status / layout */
  function paintConn() {
    if (!E.conn) return;
    var st = S.wsState, host = CFG.wsUrl.replace(/^wss?:\/\//, '').replace(/\/.*$/, '');
    E.conn.className = 'na-conn' + (st === 'open' ? ' live' : st === 'connecting' ? ' wait' : '');
    E.conn.lastChild.textContent = st === 'open' ? 'Live  ' + host : st === 'connecting' ? 'Connecting' : 'Demo data';
  }
  function paintSources() {
    if (!V) return;
    V.querySelectorAll('.na-src[data-src]').forEach(function (n) {
      var t = n.dataset.src; if (t === 'leak') return;
      var live = isLive(t);
      n.textContent = live ? 'Live' : 'Demo'; n.classList.toggle('live', live);
    });
  }
  function renderAll() { renderDevices(); renderSpectrum(); renderRssi(); renderDnsCounts(); paintScanMeta(); }
  var layoutRaf = 0;
  function layout() {
    cancelAnimationFrame(layoutRaf);
    layoutRaf = requestAnimationFrame(function () { renderSpectrum(); drawRssi(); });
  }
  window.addEventListener('resize', function () { if (S.open) layout(); });
  window.addEventListener('orientationchange', function () { if (S.open) setTimeout(layout, 250); });

  /* ----------------------------------------------------------------- public */
  window.NetAudit = { open: function () { open(); }, close: function () { close(); }, isOpen: function () { return S.open; } };

  if (location.hash === CFG.hash) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { open(false); });
    else open(false);
  }
})();
