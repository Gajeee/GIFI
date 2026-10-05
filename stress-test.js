/* ==========================================================================
   Stress test panel - stress-test.js (browser only)
   Opens from any [data-stress-open] link. Exposes window.StressTest { open, close, isOpen }.
   Reuses .na-view styles from network-audit.css plus stress-test.css.
   ========================================================================== */
(function () {
  'use strict';
  if (window.StressTest) return;
  var HASH = '#stress-test', V, built = false, isOpen = false, busy = false, abort = false, lastFocus, blobUrl, gpuName = '', specsDone = false;
  var $ = function (id) { return document.getElementById('st' + id); };
  var mean = function (a) { return a.length ? a.reduce(function (x, y) { return x + y; }, 0) / a.length : 0; };
  var BACK = '<svg class="na-i" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10 3 5 8l5 5"/></svg>';

  var TEMPLATE =
    '<div class="na-top"><div class="na-wrap">' +
      '<button class="btn line sm btn-ic na-back" type="button" data-st-close>' + BACK + '<span>Back</span></button>' +
      '<span class="stamp">[ STRESS TEST ]</span>' +
      '<span class="na-conn" id="stConn"><i></i><span>Idle</span></span>' +
    '</div></div>' +
    '<div class="na-wrap na-body">' +
      '<div class="na-hero"><span class="stamp">[ CPU + GPU ]</span><h2 id="stTitle">Stress test</h2>' +
      '<p class="na-lede">Full load on every CPU thread and the GPU. Shows whether they hold speed or throttle, and gives a score. Runs in your browser, nothing is uploaded.</p></div>' +

      '<div class="st-g st-g4" style="margin-top:0">' +
        card('CPU THREADS', 'Thr') + card('GPU', 'GpuN') + card('MEMORY', 'Mem') + card('SYSTEM', 'Os') +
        card('DISPLAY', 'Dis') + card('BROWSER', 'Br') + card('POWER', 'Pw') + card('WEBGPU', 'Wg') +
      '</div>' +
      '<p class="st-note">Browsers hide the CPU model, so only thread count and architecture show. Reported memory is capped at 8 GB.</p>' +

      '<div class="na-card st-live" style="margin-top:24px">' +
        '<div><span class="stamp" id="stLbl">LOAD</span>' +
          '<div><span class="st-num" id="stLive">0.0</span><span class="st-unit" id="stUnit">Mops/s</span></div>' +
          '<p class="st-phase" id="stPhase">Pick a duration and press start. Keep the charger in and this tab visible.</p>' +
          '<div class="st-track"><i id="stProg"></i></div>' +
          '<span class="pill na" id="stStatus">● Idle</span><div class="st-cores" id="stCores"></div></div>' +
        '<div class="st-log" id="stLog"><span class="d">// waiting for test</span></div>' +
      '</div>' +
      '<canvas class="st-cv" id="stCv" width="1920" height="1080" aria-label="GPU test render"></canvas>' +
      '<div class="st-ctl">' +
        '<button class="btn fill" id="stBoth" type="button">Run both</button>' +
        '<button class="btn line" id="stCpu" type="button">CPU only</button>' +
        '<button class="btn line" id="stGpu" type="button">GPU only</button>' +
        '<div class="st-dd" id="stDdWrap">' +
          '<input type="hidden" id="stDur" value="30">' +
          '<button class="st-dd-btn" id="stDd" type="button" aria-haspopup="listbox" aria-expanded="false" aria-controls="stDdM" aria-label="Duration per test"><span id="stDdL">30 s per test</span>' +
            '<svg class="st-dd-ch" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 6l4 4 4-4"/></svg></button>' +
          '<ul class="st-dd-menu" id="stDdM" role="listbox" aria-label="Duration per test">' +
            [15, 30, 60, 120].map(function (s) { return '<li role="option" data-v="' + s + '" aria-selected="' + (s === 30) + '"><span>' + s + ' s per test</span><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3.5 8.5l3 3 6-7"/></svg></li>'; }).join('') +
          '</ul>' +
        '</div>' +
        '<button class="btn line stop" id="stStop" type="button" disabled>Stop</button>' +
      '</div>' +
      '<p class="st-note">This runs the hardware flat out. It gets hot and loud. Stop it if it gets too hot, and keep the vents clear.</p>' +

      '<h3 class="st-h">Score</h3>' +
      '<div class="na-card st-total" style="margin-top:16px"><div><span class="stamp">OVERALL SCORE</span><div class="st-num" id="stRall">—</div></div>' +
        '<div><span class="pill na" id="stTier">● Not run</span><p id="stRnote">No score yet. Scores are relative, so only compare them with other GIFI runs.</p></div></div>' +
      '<div class="st-g st-g4">' +
        '<div class="na-card st-m"><span class="stamp">CPU SCORE</span><div class="st-big" id="stRcpu">—</div><div class="st-sub" id="stRcpuS"></div></div>' +
        '<div class="na-card st-m"><span class="stamp">GPU SCORE</span><div class="st-big" id="stRgpu">—</div><div class="st-sub" id="stRgpuS"></div></div>' +
        '<div class="na-card st-m"><span class="stamp">CPU STABILITY</span><div class="st-big"><span id="stRcs">—</span><small>%</small></div><div class="st-sub" id="stRcsS"></div></div>' +
        '<div class="na-card st-m"><span class="stamp">GPU STABILITY</span><div class="st-big"><span id="stRgs">—</span><small>%</small></div><div class="st-sub" id="stRgsS"></div></div>' +
      '</div>' +
      '<div class="st-g st-g2">' +
        '<div class="na-card"><span class="stamp">CPU THROUGHPUT (MOPS/S)</span><svg class="st-sp" id="stSpC" viewBox="0 0 300 80" preserveAspectRatio="none"></svg></div>' +
        '<div class="na-card"><span class="stamp">GPU THROUGHPUT (G-ITER/S)</span><svg class="st-sp" id="stSpG" viewBox="0 0 300 80" preserveAspectRatio="none"></svg></div>' +
      '</div>' +
      '<p class="st-note">CPU score is 30% single-core and 70% all-core speed. GPU score is shader work finished per second, measured with the load raised until the GPU is the limit. Stability is the last quarter of a run against the first. Below 95% means the chip slowed down from heat or power limits.</p>' +
    '</div>';

  function card(label, id) {
    return '<div class="na-card st-card"><span class="stamp">' + label + '</span><div class="st-v" id="st' + id + '">Detecting…</div><div class="st-sub" id="st' + id + 'S"></div></div>';
  }

  /* ---------- helpers ---------- */
  function log(m, c) {
    var el = $('Log'), t = new Date().toLocaleTimeString([], { hour12: false });
    el.insertAdjacentHTML('beforeend', '\n<span class="d">' + t + '</span> ' + (c ? '<span class="' + c + '">' + m + '</span>' : m));
    el.scrollTop = el.scrollHeight;
  }
  function status(t, c) { var s = $('Status'); s.textContent = '● ' + t; s.className = 'pill ' + (c || 'na'); }
  function conn(on, txt) { var c = $('Conn'); c.className = 'na-conn' + (on ? ' wait' : ''); c.lastChild.textContent = txt; }
  function setLive(v, unit, lbl, phase, p) {
    $('Live').textContent = v; $('Unit').textContent = unit; $('Lbl').textContent = lbl;
    if (phase) $('Phase').textContent = phase; $('Prog').style.width = Math.min(100, p) + '%';
  }
  function spark(el, a) {
    if (!a.length) { el.innerHTML = ''; return; }
    var max = Math.max.apply(null, a) * 1.15 || 1, n = Math.max(a.length - 1, 1);
    el.innerHTML = '<polyline fill="none" stroke="#c5ff4a" stroke-width="1.5" vector-effect="non-scaling-stroke" points="' +
      a.map(function (v, i) { return (i / n * 300).toFixed(1) + ',' + (78 - v / max * 74).toFixed(1); }).join(' ') + '"/>';
  }
  function stability(a) {
    if (a.length < 4) return null;
    var k = Math.max(1, Math.floor(a.length / 4)), f = mean(a.slice(1, 1 + k));
    return f ? Math.min(100, Math.round(mean(a.slice(-k)) / f * 100)) : null;
  }
  function stabLabel(s) { return s === null ? 'Too short to judge' : s >= 95 ? 'Holds steady' : s >= 85 ? 'Slight throttling' : 'Throttles under load'; }

  /* ---------- device specs ---------- */
  function specs() {
    if (specsDone) return; specsDone = true;
    var n = navigator, u = n.userAgentData, ua = n.userAgent;
    Promise.resolve(u && u.getHighEntropyValues ? u.getHighEntropyValues(['architecture', 'bitness', 'platformVersion']) : {}).catch(function () { return {}; }).then(function (h) {
      $('Thr').textContent = n.hardwareConcurrency ? n.hardwareConcurrency + ' threads' : 'Not reported';
      var arch = h.architecture ? h.architecture + (h.bitness ? ', ' + h.bitness + '-bit' : '') : (/arm|aarch/i.test(ua) ? 'arm' : /x86|win64|x64|intel|wow64/i.test(ua) ? 'x86' : '');
      $('ThrS').textContent = arch ? 'Architecture: ' + arch : 'CPU model hidden by browser';
      var dm = n.deviceMemory; $('Mem').textContent = dm ? (dm >= 8 ? '8+ GB' : dm + ' GB') : 'Not reported';
      var os = (u && u.platform) || n.platform || 'Unknown';
      if (os === 'Windows' && h.platformVersion) os = parseInt(h.platformVersion, 10) >= 13 ? 'Windows 11' : 'Windows 10';
      $('Os').textContent = os;
      $('Dis').textContent = screen.width + '×' + screen.height + ' @' + (devicePixelRatio || 1) + 'x';
      var br = u && u.brands && (u.brands.filter(function (b) { return !/not.?a.?brand|chromium/i.test(b.brand); }).pop() || u.brands[u.brands.length - 1]);
      $('Br').textContent = br ? br.brand + ' ' + br.version : (ua.match(/(Firefox|Version)\/[\d.]+/) || ['Unknown'])[0].replace('Version', 'Safari');
      try {
        var gl = document.createElement('canvas').getContext('webgl'), ex = gl.getExtension('WEBGL_debug_renderer_info');
        var r = ex ? gl.getParameter(ex.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER), p = r.split(',');
        gpuName = (p[1] || p[0]).trim().replace(/^ANGLE \(/, '').replace(/^ANGLE Metal Renderer:\s*/, '').replace(/\s*(Direct3D|vs_\d|OpenGL).*$/i, '').replace(/\)$/, '');
        $('GpuN').textContent = gpuName;
        if (/swiftshader|llvmpipe|software/i.test(r)) $('GpuNS').textContent = 'Software rendering: GPU test will be very slow';
      } catch (e) { $('GpuN').textContent = 'WebGL unavailable'; }
      if (n.getBattery) n.getBattery().then(function (b) { $('Pw').textContent = Math.round(b.level * 100) + '% ' + (b.charging ? 'charging' : 'on battery'); }).catch(function () { $('Pw').textContent = 'Not reported'; });
      else $('Pw').textContent = 'Not reported';
      if (n.gpu) n.gpu.requestAdapter().then(function (a) {
        $('Wg').textContent = 'Supported'; var i = (a && a.info) || {};
        if (!$('GpuNS').textContent && (i.description || i.architecture)) $('GpuNS').textContent = 'Architecture: ' + (i.architecture || i.description);
      }).catch(function () { $('Wg').textContent = 'No adapter'; });
      else $('Wg').textContent = 'Not supported';
    });
  }

  /* ---------- CPU test ---------- */
  /* Each worker runs two kernels back to back: four independent sin/sqrt/hash chains (keeps the
     out-of-order core and its FP units full, unlike a single dependent chain) and a 64x64 float64
     matrix multiply (keeps the FMA/vector units and the L1/L2 caches busy) and a sweep over 8 MB per thread (pushes the
     L3 cache and memory controller). */
  var WSRC = [
    'let run=true;onmessage=e=>{if(e.data==="stop")run=false};',
    'const N=64,A=new Float64Array(N*N),B=new Float64Array(N*N),C=new Float64Array(N*N),M=new Float64Array(1<<20);',
    'for(let i=0;i<N*N;i++){A[i]=Math.sin(i)+1.5;B[i]=Math.cos(i*.7)+1.5}',
    'let a=1.234567,b=2.345678,c=3.456789,d=4.567891,h=2166136261|0;',
    'function loop(){const s=performance.now();let n=0;',
    'while(performance.now()-s<250){',
    'for(let i=0;i<4000;i++){',
    'a=Math.sin(a)*1.0001+Math.sqrt(a*a+1.5);b=Math.sin(b)*1.0001+Math.sqrt(b*b+1.5);',
    'c=Math.sin(c)*1.0001+Math.sqrt(c*c+1.5);d=Math.sin(d)*1.0001+Math.sqrt(d*d+1.5);',
    'h=Math.imul(h^(((a+b+c+d)*1e6)|0),16777619);',
    'a=a%7+.1;b=b%7+.1;c=c%7+.1;d=d%7+.1}',
    'n+=16000;',
    'for(let i=0;i<N;i++)for(let k=0;k<N;k++){const v=A[i*N+k];for(let j=0;j<N;j++)C[i*N+j]+=v*B[k*N+j]}',
    'n+=N*N*N/4;',
    'for(let i=0;i<M.length;i+=8)M[i]=M[i]*.999999+b*1e-9;',
    'n+=M.length/4;',
    'for(let i=0;i<N*N;i++){A[i]=C[i]%1+.5;C[i]=0}',
    '}',
    'postMessage({c:n,t:performance.now()-s,h:h});if(run)setTimeout(loop,0)}loop();'
  ].join('');
  function burn(n, secs, tick) {
    return new Promise(function (res) {
      blobUrl = blobUrl || URL.createObjectURL(new Blob([WSRC], { type: 'text/javascript' }));
      var ws = [], rate = new Array(n).fill(0), samples = [], t0 = performance.now(), cores = $('Cores'), bars = [];
      cores.innerHTML = '';
      if (n > 1 && n <= 64) for (var k = 0; k < n; k++) { cores.insertAdjacentHTML('beforeend', '<i><b></b></i>'); bars.push(cores.lastChild.firstChild); }
      try {
        for (var i = 0; i < n; i++) (function (i) { var w = new Worker(blobUrl); w.onmessage = function (e) { rate[i] = e.data.c / e.data.t / 1000; }; ws.push(w); })(i);
      } catch (err) { log('Could not start workers: ' + String(err.message).replace(/[<>&]/g, ''), 'e'); ws.forEach(function (w) { w.terminate(); }); return res(null); }
      var iv = setInterval(function () {
        var el = (performance.now() - t0) / 1000, tot = rate.reduce(function (a, b) { return a + b; }, 0), mx = Math.max.apply(null, rate) || 1;
        bars.forEach(function (b, i) { b.style.height = (rate[i] / mx * 100) + '%'; });
        if (tot > 0) samples.push(tot);
        tick(tot, el);
        if (el >= secs || abort) { clearInterval(iv); ws.forEach(function (w) { w.terminate(); }); res(samples); }
      }, 500);
    });
  }
  function cpuTest(secs) {
    var n = Math.max(1, navigator.hardwareConcurrency || 4);
    status('CPU single-core', 'mid'); log('CPU: single-core pass, 5 s');
    return burn(1, 5, function (v, el) { setLive(v.toFixed(1), 'Mops/s', 'CPU · 1 CORE', 'Single-core pass.', el / 5 * 100); }).then(function (s1) {
      if (!s1 || abort) return null;
      var single = mean(s1.slice(1)); log('Single-core: ' + single.toFixed(1) + ' Mops/s', 't');
      status('CPU all cores', 'mid'); log('CPU: loading ' + n + ' threads for ' + secs + ' s');
      var sm = [];
      return burn(n, secs, function (v, el) {
        sm.push(v); spark($('SpC'), sm);
        setLive(v.toFixed(0), 'Mops/s', 'CPU · ' + n + ' THREADS', 'All ' + n + ' threads at full load.', el / secs * 100);
      }).then(function (s2) {
        if (!s2 || !s2.length) return null;
        var multi = mean(s2.slice(1)), st = stability(s2);
        log('All-core: ' + multi.toFixed(0) + ' Mops/s, stability ' + (st === null ? 'n/a' : st + '%'), 't');
        return { single: single, multi: multi, st: st, score: Math.round((single * .3 + multi * .7) * 10) };
      });
    });
  }

  /* ---------- GPU test ---------- */
  /* A browser draws at most one frame per screen refresh, so one shader pass per frame leaves a fast
     GPU idle most of the time. Instead each frame issues many full-screen passes, and a short
     calibration phase raises the pass count until one frame takes ~100-180 ms of real GPU time. After
     that the GPU never waits for the display. The pass count is then frozen for the scored run, so a
     falling score really means the GPU slowed down. Passes are alpha-blended so none can be skipped. */
  var ITER = 256, GT_LO = 100, GT_HI = 180, MAX_PASSES = 65536, CAL_MS = 6000;
  function gpuTest(secs) {
    return new Promise(function (res) {
      var cv = $('Cv'); cv.style.display = 'block';
      var gl = cv.getContext('webgl', { alpha: false, antialias: false, depth: false, stencil: false, powerPreference: 'high-performance' });
      if (!gl) { log('WebGL is not available in this browser.', 'e'); cv.style.display = 'none'; return res(null); }
      var mk = function (t, src) { var s = gl.createShader(t); gl.shaderSource(s, src); gl.compileShader(s); return s; }, pr = gl.createProgram();
      gl.attachShader(pr, mk(gl.VERTEX_SHADER, 'attribute vec2 p;void main(){gl_Position=vec4(p,0.,1.);}'));
      gl.attachShader(pr, mk(gl.FRAGMENT_SHADER, 'precision highp float;uniform float t;uniform vec2 r;void main(){vec2 p=(gl_FragCoord.xy/r-.5)*3.;float a=0.;for(int i=0;i<' + ITER + ';i++){p=vec2(sin(p.y*1.3+t)+cos(p.x*.7),cos(p.x*1.1-t)+sin(p.y*.9));a+=length(p)*.006;}gl_FragColor=vec4(vec3(.77,1.,.29)*fract(a),.35);}'));
      gl.linkProgram(pr);
      if (!gl.getProgramParameter(pr, gl.LINK_STATUS)) { log('Shader failed to compile on this GPU.', 'e'); cv.style.display = 'none'; return res(null); }
      gl.useProgram(pr);
      gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
      var loc = gl.getAttribLocation(pr, 'p'); gl.enableVertexAttribArray(loc); gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
      gl.uniform2f(gl.getUniformLocation(pr, 'r'), cv.width, cv.height);
      gl.enable(gl.BLEND); gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
      var ut = gl.getUniformLocation(pr, 't'), px = new Uint8Array(4), samples = [], passes = 1, cal = true, calOk = 0, frames = 0;
      var gPerPass = cv.width * cv.height * ITER / 1e9, tStart = performance.now(), t0 = tStart, last = tStart;
      status('GPU calibrating', 'mid'); log('GPU: ' + cv.width + '×' + cv.height + ', calibrating load');
      setLive('…', 'G-iter/s', 'GPU · ' + (gpuName || 'RENDER'), 'Calibrating GPU load.', 0);
      /* draws n passes, then blocks until the GPU has finished them; returns how long that took in ms */
      function draw(n) {
        var s = performance.now(), ts = (s - tStart) / 1000;
        for (var i = 0; i < n; i++) { gl.uniform1f(ut, ts + i * 0.013); gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4); }
        gl.readPixels(0, 0, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, px);
        return performance.now() - s;
      }
      (function frame() {
        var now = performance.now(), dt = draw(passes);
        if (cal && abort) { cv.style.display = 'none'; return res(null); }
        if (cal) {
          if (dt < GT_LO && passes < MAX_PASSES) { passes = Math.min(MAX_PASSES, Math.max(passes + 1, Math.round(passes * Math.min(3, GT_LO * 1.3 / Math.max(dt, .5))))); calOk = 0; }
          else if (dt > GT_HI) { passes = Math.max(1, Math.floor(passes * GT_LO * 1.3 / dt)); calOk = 0; }
          else calOk++;
          if (calOk >= 3 || now - tStart >= CAL_MS) {
            cal = false; t0 = last = performance.now(); frames = 0;
            status('GPU rendering', 'mid');
            log('GPU: ' + passes + ' passes per frame, about ' + dt.toFixed(0) + ' ms of GPU work each. Scored run: ' + secs + ' s.');
          }
          return requestAnimationFrame(frame);
        }
        frames++;
        if (now - last >= 500) {
          var g = frames * passes * gPerPass / ((now - last) / 1000); frames = 0; last = now; samples.push(g); spark($('SpG'), samples);
          setLive(g >= 100 ? g.toFixed(0) : g.toFixed(1), 'G-iter/s', 'GPU · ' + (gpuName || 'RENDER'), passes + ' passes per frame.', (now - t0) / 1000 / secs * 100);
        }
        if ((now - t0) / 1000 >= secs || abort) {
          cv.style.display = 'none';
          if (samples.length < 2) return res(null);
          var f = mean(samples.slice(1)), fps = f / (passes * gPerPass);
          log('GPU: ' + f.toFixed(1) + ' G-iter/s (' + passes + ' passes, ' + fps.toFixed(1) + ' frames/s)', 't');
          return res({ fps: fps, passes: passes, g: f, st: stability(samples), score: Math.round(f * 10) });
        }
        requestAnimationFrame(frame);
      })();
    });
  }

  /* ---------- run + score ---------- */
  function show(cpu, gpu) {
    if (cpu) { $('Rcpu').textContent = cpu.score; $('RcpuS').textContent = '1-core ' + cpu.single.toFixed(0) + ' · all-core ' + cpu.multi.toFixed(0) + ' Mops/s'; $('Rcs').textContent = cpu.st === null ? '—' : cpu.st; $('RcsS').textContent = stabLabel(cpu.st); }
    if (gpu) { $('Rgpu').textContent = gpu.score; $('RgpuS').textContent = gpu.g.toFixed(gpu.g >= 100 ? 0 : 1) + ' G-iter/s · ' + gpu.passes + ' passes · ' + gpu.fps.toFixed(1) + ' frames/s'; $('Rgs').textContent = gpu.st === null ? '—' : gpu.st; $('RgsS').textContent = stabLabel(gpu.st); }
    var sc = [cpu && cpu.score, gpu && gpu.score].filter(Boolean);
    if (!sc.length) return;
    var all = Math.round(mean(sc)), t = all < 400 ? ['Entry', 'no'] : all < 1200 ? ['Mainstream', 'mid'] : all < 2500 ? ['High end', ''] : ['Extreme', ''];
    $('Rall').textContent = all; $('Tier').textContent = '● ' + t[0]; $('Tier').className = 'pill ' + t[1];
    $('Rnote').textContent = sc.length === 2 ? 'Average of CPU and GPU scores.' : 'One test only. Run both for an overall score.';
  }
  function lock(on) { ['Both', 'Cpu', 'Gpu'].forEach(function (i) { $(i).disabled = on; }); $('Stop').disabled = !on; }
  function run(mode) {
    if (busy) return;
    busy = true; abort = false; lock(true); conn(true, 'Running');
    $('Log').innerHTML = '<span class="d">// test started</span>';
    var secs = +$('Dur').value, cpu = null, gpu = null;
    Promise.resolve(mode !== 'gpu' ? cpuTest(secs) : null).then(function (c) {
      cpu = c; return mode !== 'cpu' && !abort ? gpuTest(secs) : null;
    }).then(function (g) {
      gpu = g; show(cpu, gpu);
      var ok = cpu || gpu;
      status(abort ? 'Stopped' : ok ? 'Done' : 'Failed', abort ? 'mid' : ok ? '' : 'no');
      setLive($('Live').textContent, $('Unit').textContent, 'FINISHED', ok ? 'Done.' : 'Nothing ran. See the log.', 100);
      log(abort ? 'Stopped.' : 'Finished.', abort ? 'w' : 't');
      busy = false; $('Cores').innerHTML = ''; lock(false); conn(false, 'Idle');
      if (ok && !abort && isOpen) $('Rall').scrollIntoView({ block: 'center' });
    });
  }

  /* ---------- duration dropdown ---------- */
  function setDd(on) { $('DdWrap').classList.toggle('open', on); $('Dd').setAttribute('aria-expanded', on); }
  function pickDd(v) {
    $('Dur').value = v; $('DdL').textContent = v + ' s per test';
    Array.prototype.forEach.call($('DdM').children, function (li) { li.setAttribute('aria-selected', li.getAttribute('data-v') === v); });
  }

  /* ---------- view ---------- */
  function build() {
    if (built) return;
    V = document.createElement('div'); V.className = 'na-view st-view'; V.id = 'stView';
    V.setAttribute('role', 'dialog'); V.setAttribute('aria-modal', 'true'); V.setAttribute('aria-labelledby', 'stTitle'); V.setAttribute('aria-hidden', 'true');
    V.innerHTML = TEMPLATE; document.body.appendChild(V);
    V.addEventListener('click', function (e) { if (e.target.closest('[data-st-close]')) close(); });
    $('Both').onclick = function () { run('both'); }; $('Cpu').onclick = function () { run('cpu'); }; $('Gpu').onclick = function () { run('gpu'); };
    $('Stop').onclick = function () { abort = true; };
    $('Dd').onclick = function () { setDd(!$('DdWrap').classList.contains('open')); };
    $('DdM').addEventListener('click', function (e) { var li = e.target.closest('li'); if (li) { pickDd(li.getAttribute('data-v')); setDd(false); $('Dd').focus(); } });
    $('Dd').addEventListener('keydown', function (e) {
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
      e.preventDefault();
      var vs = ['15', '30', '60', '120'], i = vs.indexOf($('Dur').value) + (e.key === 'ArrowDown' ? 1 : -1);
      if (i >= 0 && i < vs.length) pickDd(vs[i]);
    });
    V.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && $('DdWrap').classList.contains('open')) { e.stopPropagation(); setDd(false); $('Dd').focus(); }
    });
    V.addEventListener('click', function (e) { if (!e.target.closest('#stDdWrap')) setDd(false); });
    built = true;
  }
  function open(push) {
    if (isOpen) return; build(); isOpen = true; lastFocus = document.activeElement;
    V.setAttribute('aria-hidden', 'false'); document.documentElement.classList.add('na-lock'); V.scrollTop = 0;
    requestAnimationFrame(function () { V.classList.add('open'); var b = V.querySelector('[data-st-close]'); if (b) b.focus({ preventScroll: true }); });
    if (push !== false && location.hash !== HASH) { try { history.pushState({ st: 1 }, '', HASH); } catch (e) {} }
    specs();
  }
  function close(fromPop) {
    if (!isOpen) return; isOpen = false; abort = true; setDd(false);
    V.classList.remove('open'); V.setAttribute('aria-hidden', 'true'); document.documentElement.classList.remove('na-lock');
    if (!fromPop) { try { if (history.state && history.state.st) history.back(); else if (location.hash === HASH) history.replaceState(null, '', location.pathname + location.search); } catch (e) {} }
    if (lastFocus && lastFocus.focus) { try { lastFocus.focus({ preventScroll: true }); } catch (e) {} }
  }
  document.addEventListener('click', function (e) { if (e.target.closest('[data-stress-open]')) { e.preventDefault(); open(); } });
  document.addEventListener('keydown', function (e) {
    if (!isOpen) return;
    if (e.key === 'Escape') close();
    else if (e.key === 'Tab') {
      var f = V.querySelectorAll('button:not([disabled]),select,a[href]'); if (!f.length) return;
      var a = f[0], z = f[f.length - 1];
      if (e.shiftKey && document.activeElement === a) { e.preventDefault(); z.focus(); }
      else if (!e.shiftKey && document.activeElement === z) { e.preventDefault(); a.focus(); }
    }
  });
  document.addEventListener('visibilitychange', function () { if (busy && document.hidden) log('Tab hidden: the browser may slow the test. Keep it visible.', 'w'); });
  window.addEventListener('popstate', function () { if (location.hash === HASH) open(false); else close(true); });
  if (location.hash === HASH) document.addEventListener('DOMContentLoaded', function () { open(false); });
  window.StressTest = { open: function () { open(); }, close: function () { close(); }, isOpen: function () { return isOpen; } };
})();
