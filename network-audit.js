/* ==========================================================================
   Network Security Audit panel  -  network-audit.js   (browser only)
   Self-contained module. Injects its own DOM, binds to any element with
   [data-audit-open], and exposes window.NetAudit { open, close, isOpen }.

   Everything here is measured live in your browser. No backend, no sample data.
     LIVE LATENCY      probes speed.cloudflare.com once a second (RTT, jitter, loss)
     SECURITY CHECKS   public IP, HTTPS, WebRTC address exposure, IPv6, encrypted DNS,
                       privacy signals
   Browsers cannot read ARP tables, Wi-Fi scans, RSSI or DNS traffic, so none of
   those are shown.

   Optional config: window.NET_AUDIT_CONFIG = { hash }
   ========================================================================== */
(function () {
  'use strict';
  if (window.NetAudit) return;

  var CFG = Object.assign({ hash: '#network-audit', window: 90 }, window.NET_AUDIT_CONFIG || {});
  var PING = 'https://speed.cloudflare.com/__down?bytes=0&r=';
  var META = 'https://speed.cloudflare.com/meta';

  /* ------------------------------------------------------------------ util */
  var clamp = function (v, a, b) { return Math.min(b, Math.max(a, v)); };
  var pad = function (n) { return String(n).padStart(2, '0'); };
  var clock = function (d) { d = d || new Date(); return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()); };
  var esc = function (s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  };
  var svgIcon = function (p) {
    return '<svg class="na-i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + p + '</svg>';
  };
  var ICON = {
    back: svgIcon('<path d="M19 12H5M11 6l-6 6 6 6"/>'),
    pause: svgIcon('<path d="M8 5v14M16 5v14"/>'),
    play: svgIcon('<path d="M7 5l11 7-11 7z"/>'),
    shield: svgIcon('<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>'),
    retry: svgIcon('<path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7"/>')
  };
  function fetchTimeout(url, ms, opts) {
    var ctl = new AbortController(), t = setTimeout(function () { ctl.abort(); }, ms);
    return fetch(url, Object.assign({ cache: 'no-store', signal: ctl.signal }, opts || {}))
      .then(function (r) { clearTimeout(t); return r; }, function (e) { clearTimeout(t); throw e; });
  }
  var uniq = function (a) { return a.filter(function (x, i) { return x && a.indexOf(x) === i; }); };

  /* ----------------------------------------------------------------- state */
  var S = {
    open: false, built: false, lat: [], run: 0, paused: false, hover: null, client: null,
    timers: {}
  };
  var V, E = {}, lastFocus = null, colors = {};

  /* ------------------------------------------------------------------ view */
  var CHECKS = [
    ['ip', 'Public address'], ['https', 'Secure connection'], ['webrtc', 'WebRTC exposure'],
    ['ipv6', 'IPv6'], ['doh', 'Encrypted DNS'], ['privacy', 'Privacy signals']
  ];
  var TEMPLATE =
    '<div class="na-top"><div class="na-wrap">' +
      '<button class="btn line sm btn-ic na-back" type="button" data-na-close>' + ICON.back + '<span>Back</span></button>' +
      '<span class="stamp na-top-title">[ NETWORK SECURITY AUDIT ]</span>' +
      '<span class="na-conn live" id="naConn" role="status" aria-live="polite"><i></i><span>Live</span></span>' +
    '</div></div>' +
    '<div class="na-wrap na-body">' +
      '<header class="na-hero">' +
        '<div class="row"><span class="stamp">[ AUDIT PANEL ]</span><span class="stamp">B 04</span></div>' +
        '<h2 id="naTitle">Network security audit</h2>' +
        '<p class="na-lede">Live latency, jitter and loss, plus what your browser reveals about you. Measured in this tab.</p>' +
        '<p class="na-native" id="naNative"></p>' +
      '</header>' +

      '<div class="na-grid na-g4">' +
        '<div class="na-card na-m"><span class="stamp">LATENCY</span><div class="na-mv" id="sPing">—<small>ms</small></div><div class="na-ms" id="sPingS">Measuring…</div></div>' +
        '<div class="na-card na-m"><span class="stamp">JITTER</span><div class="na-mv" id="sJit">—<small>ms</small></div><div class="na-ms" id="sJitS">—</div></div>' +
        '<div class="na-card na-m"><span class="stamp">PACKET LOSS</span><div class="na-mv" id="sLoss">—<small>%</small></div><div class="na-ms" id="sLossS">—</div></div>' +
        '<div class="na-card na-m"><span class="stamp">PEAK</span><div class="na-mv" id="sMax">—<small>ms</small></div><div class="na-ms" id="sMaxS">—</div></div>' +
      '</div>' +

      /* 1. security checks */
      '<section class="na-card na-grid" style="display:block" aria-labelledby="naH1">' +
        '<div class="na-head"><span class="stamp" id="naH1">[ EXPOSURE CHECKS ]</span><span class="na-src" id="naSecSrc">Checking</span></div>' +
        '<div class="na-chk" id="naChk">' +
          CHECKS.map(function (c) { return '<div data-k="' + c[0] + '"><span class="k">' + c[1] + '</span><span class="d">Checking…</span><span class="pill na">…</span></div>'; }).join('') +
        '</div>' +
        '<div class="na-tools" style="margin:18px 0 0"><button class="btn line sm btn-ic" id="naSecRun" type="button">' + ICON.retry + '<span>Re-run</span></button></div>' +
      '</section>' +

      /* 2. latency */
      '<section class="na-card na-grid" style="display:block" aria-labelledby="naHR">' +
        '<div class="na-head"><span class="stamp" id="naHR">[ LIVE LATENCY ]</span><span class="na-src live" id="naLatSrc">Live · 1 Hz</span></div>' +
        '<div class="na-read" id="naRead" data-q="none"><span class="na-big" id="naBig">—</span><span class="u">ms</span><span class="pill na" id="naQual">—</span></div>' +
        '<div class="na-canvas"><canvas id="naCv" role="img" aria-label="Round-trip latency in milliseconds, last 90 seconds"></canvas></div>' +
        '<div class="na-th" id="naTh">' +
          '<div class="g" data-q="good"><i></i><span>0 to 50 ms</span><span>Good</span></div>' +
          '<div class="f" data-q="fair"><i></i><span>51 to 150 ms</span><span>Fair</span></div>' +
          '<div class="p" data-q="poor"><i></i><span>150+ ms or lost</span><span>Poor</span></div>' +
        '</div>' +
        '<div class="na-stats" id="naRS"></div>' +
        '<div class="na-tools" style="margin:16px 0 0"><button class="btn line sm btn-ic" id="naPause" type="button">' + ICON.pause + '<span>Pause</span></button></div>' +
      '</section>'
    '</div>';

  function build() {
    if (S.built) return;
    V = document.createElement('div');
    V.className = 'na-view'; V.id = 'naView';
    V.setAttribute('role', 'dialog'); V.setAttribute('aria-modal', 'true');
    V.setAttribute('aria-labelledby', 'naTitle'); V.setAttribute('aria-hidden', 'true');
    V.innerHTML = TEMPLATE;
    document.body.appendChild(V);
    var q = function (s) { return V.querySelector(s); };
    E = {
      native: q('#naNative'), chk: q('#naChk'), secSrc: q('#naSecSrc'), secRun: q('#naSecRun'),
      read: q('#naRead'), big: q('#naBig'), qual: q('#naQual'), cv: q('#naCv'), th: q('#naTh'), rs: q('#naRS'), pause: q('#naPause'), latSrc: q('#naLatSrc'),
      sPing: q('#sPing'), sPingS: q('#sPingS'), sJit: q('#sJit'), sJitS: q('#sJitS'), sLoss: q('#sLoss'), sLossS: q('#sLossS'), sMax: q('#sMax'), sMaxS: q('#sMaxS')
    };
    bind();
    S.built = true;
  }

  function bind() {
    V.addEventListener('click', function (e) { if (e.target.closest('[data-na-close]')) close(); });
    E.secRun.addEventListener('click', runChecks);
    E.pause.addEventListener('click', function () {
      S.paused = !S.paused;
      E.pause.innerHTML = (S.paused ? ICON.play : ICON.pause) + '<span>' + (S.paused ? 'Resume' : 'Pause') + '</span>';
      E.latSrc.textContent = S.paused ? 'Paused' : 'Live'; E.latSrc.classList.toggle('live', !S.paused);
      if (!S.paused && S.open) pingLoop();
    });
    E.cv.addEventListener('pointermove', function (e) {
      var r = E.cv.getBoundingClientRect(), n = S.lat.length; if (!n) return;
      var ml = 40, mr = 10, pw = r.width - ml - mr, N = CFG.window;
      var f = clamp((e.clientX - r.left - ml) / pw, 0, 1);
      var idx = n - 1 - Math.round((1 - f) * (N - 1));
      S.hover = idx >= 0 && idx < n ? idx : null; drawLat();
    });
    E.cv.addEventListener('pointerleave', function () { S.hover = null; drawLat(); });
    if (window.ResizeObserver) {
      var ro = new ResizeObserver(function () { if (S.open) drawLat(); });
      ro.observe(E.cv.parentNode);
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
      lime: cs.getPropertyValue('--lime').trim() || '#c5ff4a', warn: '#e3c04d', bad: '#ff6b5c',
      graphite: cs.getPropertyValue('--graphite').trim() || '#252525', iron: cs.getPropertyValue('--iron').trim() || '#313131',
      ash: cs.getPropertyValue('--ash').trim() || '#7a7a8a', bone: cs.getPropertyValue('--bone').trim() || '#e5e5e5',
      chalk: cs.getPropertyValue('--chalk').trim() || '#fff'
    };
    V.setAttribute('aria-hidden', 'false');
    document.documentElement.classList.add('na-lock');
    V.scrollTop = 0;
    requestAnimationFrame(function () {
      V.classList.add('open'); drawLat();
      var b = V.querySelector('[data-na-close]'); if (b) b.focus({ preventScroll: true });
    });
    if (push !== false && location.hash !== CFG.hash) {
      try { history.pushState({ na: 1 }, '', CFG.hash); } catch (e) { /* file:// etc. */ }
    }
    nativeInfo();
    if (!S.paused) pingLoop();
    if (!S.secDone) runChecks();
  }

  function close(fromPop) {
    if (!S.open) return;
    S.open = false; S.run++;
    V.classList.remove('open'); V.setAttribute('aria-hidden', 'true');
    document.documentElement.classList.remove('na-lock');
    clearTimeout(S.timers.ping);
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
  window.addEventListener('popstate', function () { if (location.hash === CFG.hash) open(false); else close(true); });

  /* Network Information API */
  function nativeInfo() {
    var c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    var set = function () {
      E.native.textContent = c
        ? 'Browser link  →  ' + [c.effectiveType, c.downlink ? c.downlink + ' Mbps' : '', c.rtt != null ? c.rtt + ' ms RTT' : '', c.saveData ? 'data saver on' : ''].filter(Boolean).join('  •  ')
        : '';
    };
    set();
    if (c && c.addEventListener && !c._na) { c._na = 1; c.addEventListener('change', set); }
  }

  /* ------------------------------------------------------- live latency */
  function probe() {
    var t0 = performance.now();
    return fetchTimeout(PING + Math.random(), 3000).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.arrayBuffer();
    }).then(function () { return performance.now() - t0; });
  }
  function pingLoop() {
    clearTimeout(S.timers.ping);
    var run = ++S.run;
    var step = function () {
      if (!S.open || S.paused || run !== S.run) return;
      var t0 = performance.now();
      probe().then(function (ms) { return ms; }, function () { return null; }).then(function (ms) {
        if (run !== S.run) return;
        S.lat.push({ t: Date.now(), v: ms == null ? null : Math.round(ms * 10) / 10 });
        if (S.lat.length > CFG.window) S.lat.shift();
        renderLat();
        S.timers.ping = setTimeout(step, Math.max(0, 1000 - (performance.now() - t0)));
      });
    };
    /* warm-up: first request pays the TLS handshake, so it is not recorded */
    probe().catch(function () { }).then(function () { if (run === S.run) step(); });
  }
  var qOf = function (v) { return v == null || v > 150 ? 'poor' : v > 50 ? 'fair' : 'good'; };
  var QL = { good: ['Good', ''], fair: ['Fair', 'warn'], poor: ['Poor', 'bad'] };
  function latStats() {
    var all = S.lat, ok = all.filter(function (p) { return p.v != null; }).map(function (p) { return p.v; });
    var j = 0; for (var i = 1; i < ok.length; i++) j += Math.abs(ok[i] - ok[i - 1]);
    return {
      n: all.length, ok: ok.length, loss: all.length ? (all.length - ok.length) / all.length * 100 : 0,
      min: ok.length ? Math.min.apply(null, ok) : null, max: ok.length ? Math.max.apply(null, ok) : null,
      avg: ok.length ? ok.reduce(function (a, b) { return a + b; }, 0) / ok.length : null, p95: ok.length ? ok.slice().sort(function (a, b) { return a - b; })[Math.min(ok.length - 1, Math.ceil(ok.length * .95) - 1)] : null, jit: ok.length > 1 ? j / (ok.length - 1) : null
    };
  }
  var f1 = function (v) { return v >= 100 ? Math.round(v) : v.toFixed(1); };
  function renderLat() {
    if (!S.built || !S.lat.length) return;
    var last = S.lat[S.lat.length - 1], q = qOf(last.v), st = latStats();
    E.read.dataset.q = q;
    E.big.textContent = last.v == null ? 'lost' : Math.round(last.v);
    E.qual.textContent = QL[q][0]; E.qual.className = 'pill ' + QL[q][1];
    E.th.querySelectorAll('div').forEach(function (d) { d.classList.toggle('cur', d.dataset.q === q); });
    E.rs.innerHTML = '<div>Min <b>' + (st.min == null ? '—' : f1(st.min) + ' ms') + '</b></div><div>Avg <b>' + (st.avg == null ? '—' : f1(st.avg) + ' ms') + '</b></div><div>P95 <b>' + (st.p95 == null ? '—' : f1(st.p95) + ' ms') + '</b></div><div>Max <b>' + (st.max == null ? '—' : f1(st.max) + ' ms') + '</b></div>';
    E.sPing.innerHTML = (last.v == null ? '—' : Math.round(last.v)) + '<small>ms</small>';
    E.sPingS.textContent = last.v == null ? 'Probe lost' : QL[q][0];
    E.sJit.innerHTML = (st.jit == null ? '—' : f1(st.jit)) + '<small>ms</small>';
    E.sJitS.textContent = st.jit == null ? '—' : st.jit < 10 ? 'Stable' : st.jit < 30 ? 'Variable' : 'Unstable';
    E.sLoss.innerHTML = Math.round(st.loss * 10) / 10 + '<small>%</small>';
    E.sLossS.textContent = (st.n - st.ok) + ' of ' + st.n + ' probes lost';
    E.sMax.innerHTML = (st.max == null ? '—' : f1(st.max)) + '<small>ms</small>';
    E.sMaxS.textContent = st.p95 == null ? '—' : 'P95 ' + f1(st.p95) + ' ms';
    drawLat();
  }
  function drawLat() {
    var cv = E.cv; if (!cv || !S.open) return;
    var W = Math.floor(cv.parentNode.clientWidth); if (W < 120) return;
    var H = W < 520 ? 220 : 280, dpr = Math.min(window.devicePixelRatio || 1, 2.5);
    if (cv.width !== Math.round(W * dpr) || cv.height !== Math.round(H * dpr)) { cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr); cv.style.height = H + 'px'; }
    var c = cv.getContext('2d'); if (!c) return;
    c.setTransform(dpr, 0, 0, dpr, 0, 0); c.clearRect(0, 0, W, H);
    var ml = 40, mr = 10, mt = 10, mb = 22, pw = W - ml - mr, ph = H - mt - mb, N = CFG.window;
    var vs = S.lat.filter(function (p) { return p.v != null; }).map(function (p) { return p.v; });
    var top = Math.max(200, Math.ceil((vs.length ? Math.max.apply(null, vs) : 0) * 1.15 / 50) * 50);
    var Y = function (v) { return mt + ph * (1 - clamp(v, 0, top) / top); };
    var mono = '10px "JetBrains Mono",ui-monospace,Menlo,monospace';

    [[0, 50, colors.lime], [50, 150, colors.warn], [150, top, colors.bad]].forEach(function (b) {
      c.globalAlpha = .07; c.fillStyle = b[2]; c.fillRect(ml, Y(b[1]), pw, Y(b[0]) - Y(b[1])); c.globalAlpha = 1;
    });
    c.strokeStyle = colors.graphite; c.lineWidth = 1; c.fillStyle = colors.ash; c.font = mono; c.textAlign = 'right';
    uniq([0, 50, 150, Math.round(top / 2), top]).forEach(function (v) {
      var y = Math.round(Y(v)) + .5;
      c.beginPath(); c.moveTo(ml, y); c.lineTo(ml + pw, y); c.stroke();
      c.fillText(v, ml - 6, y + 3);
    });
    c.setLineDash([4, 4]);
    [[50, colors.lime], [150, colors.warn]].forEach(function (t) {
      c.strokeStyle = t[1]; c.globalAlpha = .45; c.beginPath(); c.moveTo(ml, Y(t[0])); c.lineTo(ml + pw, Y(t[0])); c.stroke(); c.globalAlpha = 1;
    });
    c.setLineDash([]);
    [[0, '-' + N + 's'], [.5, '-' + Math.round(N / 2) + 's'], [1, 'now']].forEach(function (t) {
      c.textAlign = t[0] === 0 ? 'left' : t[0] === 1 ? 'right' : 'center'; c.fillStyle = colors.ash;
      c.fillText(t[1], ml + pw * t[0], H - 6);
    });

    var n = S.lat.length; if (!n) return;
    var X = function (k) { return ml + pw * (1 - (n - 1 - k) / (N - 1)); };
    var col = function (v) { return qOf(v) === 'good' ? colors.lime : qOf(v) === 'fair' ? colors.warn : colors.bad; };
    c.lineWidth = 2; c.lineJoin = 'round'; c.lineCap = 'round';
    for (var k = 1; k < n; k++) {
      var a = S.lat[k - 1], b = S.lat[k];
      if (a.v == null || b.v == null) continue;
      c.strokeStyle = col(b.v); c.beginPath(); c.moveTo(X(k - 1), Y(a.v)); c.lineTo(X(k), Y(b.v)); c.stroke();
    }
    S.lat.forEach(function (p, k) {
      if (p.v != null) return;
      c.strokeStyle = colors.bad; c.lineWidth = 2; c.beginPath(); c.moveTo(X(k), mt + ph - 12); c.lineTo(X(k), mt + ph); c.stroke();
    });
    var li = n - 1, lp = S.lat[li];
    if (lp.v != null) {
      c.fillStyle = col(lp.v); c.shadowColor = col(lp.v); c.shadowBlur = 8; c.beginPath(); c.arc(X(li), Y(lp.v), 3.5, 0, 6.283); c.fill(); c.shadowBlur = 0;
    }
    if (S.hover != null && S.lat[S.hover]) {
      var p = S.lat[S.hover], hx = X(S.hover);
      c.strokeStyle = colors.bone; c.globalAlpha = .35; c.beginPath(); c.moveTo(hx, mt); c.lineTo(hx, mt + ph); c.stroke(); c.globalAlpha = 1;
      if (p.v != null) { c.fillStyle = colors.chalk; c.beginPath(); c.arc(hx, Y(p.v), 3, 0, 6.283); c.fill(); }
      var t = (p.v == null ? 'lost' : Math.round(p.v) + ' ms') + '  ' + clock(new Date(p.t)), tw = c.measureText(t).width + 16, bx = clamp(hx - tw / 2, ml, ml + pw - tw);
      c.fillStyle = '#000'; c.strokeStyle = colors.iron; c.fillRect(bx, mt + 4, tw, 22); c.strokeRect(bx + .5, mt + 4.5, tw - 1, 21);
      c.fillStyle = colors.chalk; c.textAlign = 'left'; c.fillText(t, bx + 8, mt + 19);
    }
  }

  /* ------------------------------------------------------ security checks */
  function loadClient() {
    if (S.client) return Promise.resolve(S.client);
    return fetchTimeout(META, 6000).then(function (r) { return r.json(); }).then(function (m) {
      S.client = { ip: m.clientIp, asn: m.asn ? +m.asn : null, org: m.asOrganization || '', country: m.country || '', city: m.city || '' };
      return S.client;
    }).catch(function () { return null; });
  }
  function setRow(k, detail, label, cls) {
    var row = E.chk.querySelector('[data-k="' + k + '"]'); if (!row) return;
    row.children[1].textContent = detail;
    var p = row.children[2]; p.textContent = label; p.className = 'pill ' + (cls || '');
  }
  function webrtcCheck(client) {
    return new Promise(function (res) {
      var pc, host = [], srflx = [], mdns = 0, done = false;
      var fin = function () {
        if (done) return; done = true; try { pc && pc.close(); } catch (e) { /* ignore */ }
        var v4 = srflx.filter(function (a) { return /^\d+\.\d+\.\d+\.\d+$/.test(a); });
        if (v4.length && client && /^\d+\.\d+\.\d+\.\d+$/.test(client.ip) && v4.indexOf(client.ip) < 0) {
          return res(['WebRTC exposes ' + v4[0] + '; sites see ' + client.ip + '. Your VPN or proxy is bypassed.', 'Leak', 'bad']);
        }
        if (host.length) return res(['Pages can read your local address ' + host[0] + ' via WebRTC.', 'Exposed', 'warn']);
        res([mdns ? 'Local addresses masked by the browser.' : 'No local or alternate address exposed.', 'Hidden', '']);
      };
      try { pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] }); } catch (e) { return res(['WebRTC unavailable.', 'Off', '']); }
      pc.createDataChannel('na');
      pc.onicecandidate = function (e) {
        if (!e.candidate) return fin();
        var m = /candidate:\S+ \d+ \S+ \d+ (\S+) \d+ typ (\w+)/.exec(e.candidate.candidate); if (!m) return;
        if (/\.local$/i.test(m[1])) { mdns++; return; }
        if (m[2] === 'host') { if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)/.test(m[1])) host.push(m[1]); }
        else if (m[2] === 'srflx') srflx.push(m[1]);
      };
      pc.createOffer().then(function (o) { return pc.setLocalDescription(o); }).catch(fin);
      setTimeout(fin, 3500);
    });
  }
  function dohCheck() {
    var name = 'na-' + Math.random().toString(36).slice(2, 10) + '.example.com';
    var targets = [['Cloudflare', 'https://cloudflare-dns.com/dns-query?name=' + name + '&type=A'], ['Google', 'https://dns.google/resolve?name=' + name + '&type=A']], i = 0;
    var next = function () {
      if (i >= targets.length) return Promise.resolve(['Cloudflare and Google DoH both unreachable from this network.', 'Blocked', 'warn']);
      var t = targets[i++], t0 = performance.now();
      return fetchTimeout(t[1], 4500, { headers: { accept: 'application/dns-json' } })
        .then(function (r) { if (!r.ok) throw 0; return r.json(); })
        .then(function () { return [t[0] + ' DoH answered in ' + Math.round(performance.now() - t0) + ' ms. Reachable; does not show your device uses it.', 'Reachable', '']; })
        .catch(next);
    };
    return next();
  }
  function runChecks() {
    E.secSrc.textContent = 'Checking'; E.secSrc.classList.remove('live');
    CHECKS.forEach(function (c) { setRow(c[0], '—', '…', 'na'); });
    var https = location.protocol === 'https:' && window.isSecureContext;
    setRow('https', https ? 'Page served over HTTPS.' : 'Page not served over HTTPS. Traffic can be read or altered.', https ? 'Secure' : 'Insecure', https ? '' : 'bad');
    var gpc = navigator.globalPrivacyControl === true, dnt = navigator.doNotTrack === '1' || window.doNotTrack === '1';
    setRow('privacy', 'Global Privacy Control: ' + (gpc ? 'on' : 'off') + '  •  Do Not Track: ' + (dnt ? 'on' : 'off'), gpc || dnt ? 'On' : 'Off', gpc || dnt ? '' : 'mid');

    var jobs = [
      loadClient().then(function (c) {
        if (!c) { setRow('ip', 'Public address lookup failed.', 'Failed', 'warn'); return null; }
        setRow('ip', [c.ip, c.org, [c.city, c.country].filter(Boolean).join(', ')].filter(Boolean).join('  •  '), 'Visible', 'na');
        return c;
      }).then(function (c) { return webrtcCheck(c).then(function (r) { setRow('webrtc', r[0], r[1], r[2]); }); }),
      fetchTimeout('https://api6.ipify.org?format=json', 5000).then(function (r) { return r.json(); })
        .then(function (j) { setRow('ipv6', j.ip + ' is your public IPv6 address.', 'Active', 'mid'); },
          function () { setRow('ipv6', 'No IPv6 connectivity.', 'Off', 'na'); }),
      dohCheck().then(function (r) { setRow('doh', r[0], r[1], r[2]); })
    ];
    Promise.all(jobs).then(function () { S.secDone = true; E.secSrc.textContent = 'Checked ' + clock(); E.secSrc.classList.add('live'); });
  }

  /* ----------------------------------------------------------------- public */
  window.NetAudit = { open: function () { open(); }, close: function () { close(); }, isOpen: function () { return S.open; } };
  if (location.hash === CFG.hash) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { open(false); });
    else open(false);
  }
})();
