/* AegisNet Lab by Rushi - the same Dual-Brain idea as the Python repo, running entirely in your browser.
   Trains a real autoencoder (26-18-6-18-26) on simulated server telemetry, then lets you attack it. No server, no libraries. */
(function (root) {
  'use strict';
  const F = ['cpu_pct', 'mem_pct', 'disk_io_mbps', 'net_in_mbps', 'net_out_mbps', 'connections', 'failed_logins', 'unique_dst_ports',
    'avg_pkt_bytes', 'dns_queries', 'http_5xx_pct', 'processes', 'file_writes'];
  const NAME = ['CPU %', 'Memory %', 'Disk I/O MB/s', 'Inbound Mbps', 'Outbound Mbps', 'Open connections', 'Failed logins/min', 'Unique ports',
    'Avg packet bytes', 'DNS queries/min', 'HTTP 5xx %', 'Processes', 'File writes/min'];
  const ATT = ['brute_force', 'ddos', 'port_scan', 'exfiltration', 'cryptominer', 'ransomware'];
  const PLAY = {
    brute_force: ['HIGH', 'Credential brute-force attack', ['Turn on account lock-out + login rate-limit', 'Open ticket and notify on-call engineer'], ['Block offending source IPs at the firewall', 'Force password reset for targeted accounts']],
    ddos: ['CRITICAL', 'Volumetric DDoS attack', ['Enable CDN / WAF rate-limiting profile', 'Page the on-call network engineer'], ['Null-route top offending prefixes', 'Scale out replicas behind the load balancer']],
    port_scan: ['MEDIUM', 'Network reconnaissance / port scan', ['Raise logging level on the firewall', 'Add source to watch-list'], ['Block scanning source IP']],
    exfiltration: ['CRITICAL', 'Possible data exfiltration / DNS tunnelling', ['Snapshot network flows for forensics', 'Alert security team'], ['Cut outbound traffic for this host', 'Disable the affected service account']],
    cryptominer: ['HIGH', 'Cryptojacking (unauthorised mining)', ['Capture process list for forensics', 'Open ticket for host owner'], ['Kill suspicious process tree', 'Isolate host from network']],
    ransomware: ['CRITICAL', 'Ransomware-like mass file encryption', ['Take immediate storage snapshot', 'Page incident-response team'], ['Isolate host from network NOW', 'Suspend user sessions on the host']],
    unknown_anomaly: ['MEDIUM', 'Unknown anomaly (possible zero-day)', ['Increase telemetry resolution for this host', 'Send to analyst queue with explanation'], ['Quarantine host for investigation']]
  };

  // ---------- random numbers
  function RNG(seed) {
    let s = seed >>> 0;
    const u = () => { s = (s + 0x6D2B79F5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
    u.n = () => { let a = 0; while (!a) a = u(); return Math.sqrt(-2 * Math.log(a)) * Math.cos(2 * Math.PI * u()); };
    u.range = (a, b) => a + (b - a) * u();
    u.int = (a, b) => Math.floor(a + (b - a) * u());
    u.poi = (l) => { if (l > 30) return Math.max(0, Math.round(l + Math.sqrt(l) * u.n())); const L = Math.exp(-l); let k = 0, p = 1; do { k++; p *= u(); } while (p > L); return k - 1; };
    return u;
  }

  // ---------- telemetry simulator (mirrors aegisnet/data.py)
  function baseline(t, r) {
    const load = 0.35 + 0.65 * 0.5 * (1 + Math.sin(2 * Math.PI * (((t / 60) % 24) - 9) / 24)), b = r.n(), N = (s) => r.n() * s;
    return [18 + 30 * load + 2 * b + N(3), 50 + 10 * load + N(2), 6 + 8 * load + Math.abs(N(2)), 40 + 120 * load + 12 * b + N(8),
      25 + 70 * load + 7 * b + N(6), 200 + 600 * load + 50 * b + N(30), r.poi(1 + 0.5 * load), r.poi(6 + 3 * load), 700 - 80 * load + N(50),
      r.poi(40 + 60 * load), 0.4 + Math.abs(N(0.25)), 120 + 10 * load + N(4), r.poi(30 + 40 * load)];
  }
  function episode(kind, r, dur) { return { kind, dur, k: 0, inten: r.range(0.4, 1), p: [r(), r(), r(), r()] }; }
  function inject(ep, v, r) {
    const L = (a, b, u) => a + (b - a) * u, p = ep.p, x = ep.inten * Math.min(1, (ep.k + 1) / 3) * r.range(0.85, 1.15);
    switch (ep.kind) {
      case 'brute_force': v[6] += x * L(80, 250, p[0]); v[5] += x * L(150, 400, p[1]); v[0] += x * L(5, 12, p[2]); break;
      case 'ddos': v[3] *= 1 + x * L(3, 8, p[0]); v[5] *= 1 + x * L(4, 11, p[1]); v[10] += x * L(8, 35, p[2]); v[0] += x * L(25, 45, p[3]); v[8] *= 1 - 0.6 * x; break;
      case 'port_scan': v[7] += x * L(400, 2000, p[0]); v[8] *= 1 - 0.85 * x; v[5] += x * L(300, 900, p[1]); break;
      case 'exfiltration': v[4] = v[4] * (1 + x * L(2, 4, p[0])) + x * L(60, 200, p[1]); v[9] += x * L(300, 800, p[2]); v[2] += x * L(15, 35, p[3]); break;
      case 'cryptominer': v[0] += x * L(40, 55, p[0]); v[11] += x * L(15, 40, p[1]); v[1] += x * L(8, 15, p[2]); v[4] += x * L(5, 15, p[3]); break;
      case 'ransomware': v[12] = v[12] * (1 + x * L(8, 20, p[0])) + x * L(1500, 4000, p[1]); v[2] += x * L(60, 120, p[2]); v[0] += x * L(20, 35, p[3]); v[11] += x * L(20, 60, p[0]); v[1] += x * L(8, 15, p[1]); break;
      case 'flash_crowd': v[3] *= 1 + x * L(1.2, 2, p[0]); v[5] *= 1 + x * L(1, 1.8, p[1]); v[0] += x * L(8, 18, p[2]); v[10] += x * L(0.2, 1, p[3]); v[4] *= 1 + 0.5 * x; break;
    }
    ep.k++;
    for (let i = 0; i < 13; i++) v[i] = Math.max(0, v[i]);
    v[0] = Math.min(100, v[0]); v[1] = Math.min(100, v[1]); v[10] = Math.min(100, v[10]);
  }

  // ---------- features: log1p level + change vs previous 5-minute mean (26 inputs)
  class Feat {
    constructor() { this.h = []; }
    step(v) {
      const x = v.map(Math.log1p), out = new Float64Array(26), n = this.h.length;
      for (let i = 0; i < 13; i++) {
        let m = x[i];
        if (n) { m = 0; for (const q of this.h) m += q[i]; m /= n; }
        out[i] = x[i]; out[13 + i] = x[i] - m;
      }
      this.h.push(x); if (this.h.length > 5) this.h.shift();
      return out;
    }
  }

  // ---------- tiny neural network (backprop + Adam), same maths as aegisnet/nn.py
  class Net {
    constructor(sizes, acts, r) {
      this.t = 0;
      this.L = acts.map((act, i) => {
        const n = sizes[i], o = sizes[i + 1], sc = Math.sqrt(1 / n), W = new Float64Array(n * o);
        for (let q = 0; q < W.length; q++) W[q] = r.n() * sc;
        const z = (k) => new Float64Array(k);
        return { n, o, act, W, b: z(o), mW: z(n * o), vW: z(n * o), mb: z(o), vb: z(o) };
      });
    }
    forward(X, m) {
      let a = X;
      for (const l of this.L) {
        l.x = a;
        const z = new Float64Array(m * l.o);
        for (let i = 0; i < m; i++) {
          const zi = i * l.o;
          for (let j = 0; j < l.o; j++) z[zi + j] = l.b[j];
          for (let k = 0; k < l.n; k++) {
            const xv = a[i * l.n + k], wk = k * l.o;
            for (let j = 0; j < l.o; j++) z[zi + j] += xv * l.W[wk + j];
          }
        }
        if (l.act === 'tanh') for (let q = 0; q < z.length; q++) z[q] = Math.tanh(z[q]);
        l.a = z; a = z;
      }
      return a;
    }
    backward(g, m, lr) {
      this.t++;
      const b1 = 0.9, b2 = 0.999, c1 = 1 - Math.pow(b1, this.t), c2 = 1 - Math.pow(b2, this.t);
      for (let li = this.L.length - 1; li >= 0; li--) {
        const l = this.L[li];
        if (l.act === 'tanh') for (let q = 0; q < g.length; q++) g[q] *= 1 - l.a[q] * l.a[q];
        const dW = new Float64Array(l.n * l.o), db = new Float64Array(l.o), gin = li ? new Float64Array(m * l.n) : null;
        for (let i = 0; i < m; i++) {
          const gi = i * l.o;
          for (let j = 0; j < l.o; j++) db[j] += g[gi + j];
          for (let k = 0; k < l.n; k++) {
            const xv = l.x[i * l.n + k], wk = k * l.o;
            let s = 0;
            for (let j = 0; j < l.o; j++) { dW[wk + j] += xv * g[gi + j]; s += g[gi + j] * l.W[wk + j]; }
            if (gin) gin[i * l.n + k] = s;
          }
        }
        for (const [P, G, M, V] of [[l.W, dW, l.mW, l.vW], [l.b, db, l.mb, l.vb]])
          for (let q = 0; q < P.length; q++) {
            M[q] = b1 * M[q] + (1 - b1) * G[q]; V[q] = b2 * V[q] + (1 - b2) * G[q] * G[q];
            P[q] -= lr * (M[q] / c1) / (Math.sqrt(V[q] / c2) + 1e-8);
          }
        g = gin;
      }
    }
  }

  // ---------- model: autoencoder + error-signature prototypes
  const tick0 = () => new Promise((res) => setTimeout(res, 0));
  function makeNormal(days, seed) {
    const r = RNG(seed), n = days * 1440, feat = new Feat(), X = new Float64Array(n * 26);
    let ep = null, next = 120 + r.int(90, 360);
    for (let t = 0; t < n; t++) {
      const v = baseline(t, r);
      if (!ep && t === next) ep = episode('flash_crowd', r, r.int(8, 30));
      if (ep) { inject(ep, v, r); if (ep.k >= ep.dur) { ep = null; next = t + r.int(90, 360); } }
      X.set(feat.step(v), t * 26);
    }
    return X;
  }
  const std = (m, z, out) => { for (let i = 0; i < 26; i++) out[i] = Math.max(-20, Math.min(20, (z[i] - m.mu[i]) / m.sd[i])); return out; };
  function analyse(m, z) {
    const x = std(m, z, new Float64Array(26)), R = m.net.forward(x, 1);
    let err = 0; const a = new Float64Array(13);
    for (let i = 0; i < 26; i++) { const e = (x[i] - R[i]) * (x[i] - R[i]); err += e; a[i % 13] += e; }
    let sum = 0; for (let i = 0; i < 13; i++) sum += a[i];
    const share = a.map((v) => v / (sum + 1e-12)), exp = [];
    for (let i = 0; i < 13; i++) exp.push(Math.expm1(R[i] * m.sd[i] + m.mu[i]));
    return { score: err / 26 / m.thr, share, exp };
  }
  const cos = (a, b) => { let d = 0, p = 0, q = 0; for (let i = 0; i < a.length; i++) { d += a[i] * b[i]; p += a[i] * a[i]; q += b[i] * b[i]; } return d / (Math.sqrt(p * q) + 1e-12); };

  async function train(o) {
    o = Object.assign({ days: 10, epochs: 16, seed: 7, onEpoch: null }, o);
    const r = RNG(o.seed), X = makeNormal(o.days, 1), n = X.length / 26;
    const mu = new Float64Array(26), sd = new Float64Array(26);
    for (let i = 0; i < n; i++) for (let j = 0; j < 26; j++) mu[j] += X[i * 26 + j] / n;
    for (let i = 0; i < n; i++) for (let j = 0; j < 26; j++) sd[j] += Math.pow(X[i * 26 + j] - mu[j], 2) / n;
    for (let j = 0; j < 26; j++) sd[j] = Math.sqrt(sd[j]) + 1e-6;
    const m = { mu, sd, net: new Net([26, 18, 6, 18, 26], ['tanh', 'tanh', 'tanh', 'linear'], r), thr: 1, proto: {}, sig: {}, forget: new Set(), losses: [] };
    const Z = new Float64Array(n * 26);
    for (let i = 0; i < n; i++) std(m, X.subarray(i * 26, i * 26 + 26), Z.subarray(i * 26, i * 26 + 26));
    const idx = Array.from({ length: n }, (_, i) => i);
    for (let i = n - 1; i > 0; i--) { const j = r.int(0, i + 1); [idx[i], idx[j]] = [idx[j], idx[i]]; }
    const nt = Math.floor(0.85 * n), B = 256, xb = new Float64Array(B * 26);
    for (let ep = 0; ep < o.epochs; ep++) {
      const lr = 3e-3 * (0.9 * 0.5 * (1 + Math.cos(Math.PI * ep / o.epochs)) + 0.1);
      let tot = 0;
      for (let s = 0; s < nt; s += B) {
        const mb = Math.min(B, nt - s);
        for (let i = 0; i < mb; i++) xb.set(Z.subarray(idx[s + i] * 26, idx[s + i] * 26 + 26), i * 26);
        const x = xb.subarray(0, mb * 26), out = m.net.forward(x, mb), g = new Float64Array(mb * 26);
        let L = 0;
        for (let q = 0; q < g.length; q++) { const d = out[q] - x[q]; L += d * d; g[q] = 2 * d / g.length; }
        tot += L; m.net.backward(g, mb, lr);
      }
      m.losses.push(tot / (nt * 26));
      if (o.onEpoch) o.onEpoch(ep + 1, o.epochs, m.losses[ep]);
      await tick0();
    }
    const errs = [];
    for (let i = nt; i < n; i++) { const x = Z.subarray(i * 26, i * 26 + 26), R = m.net.forward(x, 1); let e = 0; for (let q = 0; q < 26; q++) e += (x[q] - R[q]) * (x[q] - R[q]); errs.push(e / 26); }
    errs.sort((a, b) => a - b); m.thr = errs[Math.floor(0.995 * (errs.length - 1))];
    // error-signature prototypes: what does each known attack "look like" to the autoencoder?
    for (const kind of ATT) {
      const sh = [], rr = RNG(100 + ATT.indexOf(kind));
      for (let rep = 0; rep < 12; rep++) {
        const feat = new Feat(), ep = episode(kind, rr, 20), t0 = rr.int(0, 1440);
        for (let t = 0; t < 40; t++) {
          const v = baseline(t0 + t, rr);
          if (t >= 15 && ep.k < ep.dur) inject(ep, v, rr);
          const a = analyse(m, feat.step(v));
          if (t >= 15 && a.score > 1) sh.push(a.share);
        }
      }
      const p = new Float64Array(13);
      for (const s of sh) for (let i = 0; i < 13; i++) p[i] += s[i] / sh.length;
      const cs = sh.map((s) => cos(s, p)).sort((a, b) => a - b);
      m.proto[kind] = p; m.sig[kind] = Math.max(0.5, cs.length ? cs[Math.floor(0.05 * (cs.length - 1))] : 0.5);
    }
    return m;
  }

  // ---------- live monitor
  class Monitor {
    constructor(model, seed, t0) { this.m = model; this.r = RNG(seed || 5); this.feat = new Feat(); this.t = t0 || 600; this.ep = null; this.flags = []; this.quiet = 0; }
    launch(kind, dur) { this.ep = episode(kind, this.r, dur || 25); }
    label(share) {
      let best = null, bc = -1;
      for (const k of ATT) { if (this.m.forget.has(k)) continue; const c = cos(share, this.m.proto[k]); if (c > bc) { bc = c; best = k; } }
      return best && bc >= this.m.sig[best] ? best : 'unknown_anomaly';
    }
    step() {
      const v = baseline(this.t, this.r), truth = this.ep ? this.ep.kind : null;
      if (this.ep) { inject(this.ep, v, this.r); if (this.ep.k >= this.ep.dur) this.ep = null; }
      const a = analyse(this.m, this.feat.step(v)), flag = a.score > 1;
      const risk = 100 / (1 + Math.exp(-3 * (a.score - 1)));
      this.flags.push(flag); if (this.flags.length > 3) this.flags.shift();
      const alert = flag && (this.flags.reduce((s, f) => s + f, 0) >= 2 || risk >= 90);
      const why = [];
      if (alert) {
        const order = Array.from(a.share.keys()).sort((i, j) => a.share[j] - a.share[i]).slice(0, 3);
        order.forEach((i, n) => { if (n === 0 || a.share[i] >= 0.05) why.push({ i, name: NAME[i], share: a.share[i], obs: v[i], exp: a.exp[i] }); });
      }
      return { t: this.t++, v, truth, score: a.score, risk, alert, label: alert ? this.label(a.share) : 'normal', why };
    }
  }

  // honest self-check on unseen simulated days (episodes scheduled like the Python benchmark)
  function evaluate(model, days, seed) {
    const r = RNG(seed || 99), mon = new Monitor(model, seed || 99, 0), n = days * 1440;
    const kinds = ATT.concat(['flash_crowd', 'flash_crowd', 'flash_crowd']);
    let next = 120 + r.int(90, 360), tp = 0, fn = 0, fp = 0, tn = 0, eps = 0, hit = 0, cur = null;
    for (let t = 0; t < n; t++) {
      if (!mon.ep && t >= next) { const k = kinds[r.int(0, kinds.length)]; mon.launch(k, r.int(8, 30)); next = t + mon.ep.dur + r.int(90, 360); if (k !== 'flash_crowd') { eps++; cur = { hit: false }; } else cur = null; }
      const o = mon.step(), atk = o.truth && o.truth !== 'flash_crowd';
      if (atk) { if (o.alert) { tp++; if (cur && !cur.hit) { cur.hit = true; hit++; } } else fn++; } else if (o.alert) fp++; else tn++;
    }
    return { recall: tp / Math.max(tp + fn, 1), fpr: fp / Math.max(fp + tn, 1), episodes: eps, detected: hit, minutes: n };
  }

  const API = { F, NAME, ATT, PLAY, RNG, train, Monitor, evaluate, analyse };
  if (typeof module !== 'undefined' && module.exports) module.exports = API;
  root.AegisLab = API;

  // ================= UI =================
  function initUI(doc) {
    const $ = (id) => doc.getElementById(id);
    let model = null, mon = null, timer = null, hist = [], paused = false, speed = 120, inc = null, audit = [];
    const SEV = { CRITICAL: '#FF3D71', HIGH: '#FFB020', MEDIUM: '#8B7BFF' };
    const clock = (t) => 'day ' + (1 + Math.floor(t / 1440)) + ' ' + String(Math.floor((t % 1440) / 60)).padStart(2, '0') + ':' + String(t % 60).padStart(2, '0');
    const nice = (k) => k.replace('_', ' ');
    function fmt(x) { return x >= 100 ? Math.round(x).toLocaleString('en-US') : x.toFixed(1); }

    $('btnTrain').addEventListener('click', async () => {
      $('btnTrain').disabled = true; $('btnTrain').textContent = 'Training...';
      const t0 = Date.now();
      model = await train({ onEpoch: (e, n, l) => { $('bar').style.width = (100 * e / n) + '%'; $('trainMsg').textContent = 'epoch ' + e + '/' + n + '   reconstruction loss ' + l.toFixed(3); } });
      const ev = evaluate(model, 3);
      $('trainMsg').textContent = 'Trained in ' + ((Date.now() - t0) / 1000).toFixed(1) + ' s, 1,220 parameters, running entirely in your browser.';
      $('selfcheck').innerHTML = [[(ev.recall * 100).toFixed(1) + '%', 'attack minutes caught'], [(ev.fpr * 100).toFixed(2) + '%', 'false-alarm rate'], [ev.detected + '/' + ev.episodes, 'attacks detected'], [ev.minutes.toLocaleString('en-US'), 'unseen minutes tested']]
        .map(([a, b]) => '<div class="k"><b>' + a + '</b><span>' + b + '</span></div>').join('');
      $('btnTrain').textContent = 'Trained'; $('lab').hidden = false;
      mon = new Monitor(model, 11, 600); start();
    });
    $('attackBtns').innerHTML = ATT.map((k) => '<button data-k="' + k + '">' + (k === 'ddos' ? 'DDoS' : nice(k)) + '</button>').join('') + '<button data-k="flash_crowd" class="soft">flash crowd (harmless)</button>';
    $('attackBtns').addEventListener('click', (e) => { const k = e.target && e.target.getAttribute && e.target.getAttribute('data-k'); if (k && mon) mon.launch(k, 25); });
    $('forget').addEventListener('change', (e) => { if (!model) return; if (e.target.checked) model.forget.add('ransomware'); else model.forget.delete('ransomware'); });
    $('pause').addEventListener('click', () => { paused = !paused; $('pause').textContent = paused ? 'Resume' : 'Pause'; });
    $('speed').addEventListener('input', (e) => { speed = 270 - Number(e.target.value); start(); });
    $('approve').addEventListener('click', () => {
      if (!inc || !inc.pending.length) return;
      inc.pending.forEach((a) => { inc.done.push(a); audit.unshift(clock(mon.t) + '  human-approved  ' + a); }); inc.pending = []; renderInc();
    });
    function start() { if (timer) clearInterval(timer); timer = setInterval(frame, speed); }
    function frame() {
      if (paused || !mon) return;
      const o = mon.step(); hist.push(o); if (hist.length > 240) hist.shift();
      if (o.alert) {
        if (!inc || inc.closed || inc.label !== o.label && o.label !== 'unknown_anomaly' && inc.label === 'unknown_anomaly') {
          const pb = PLAY[o.label], auto = pb[2].slice();
          inc = { label: o.label, start: o.t, peak: o.risk, why: o.why, done: auto, pending: pb[3].slice(), closed: false, quiet: 0 };
          auto.forEach((a) => audit.unshift(clock(o.t) + '  guardian-auto    ' + a));
        } else { inc.quiet = 0; if (o.risk >= inc.peak) { inc.peak = o.risk; inc.why = o.why; } }
      } else if (inc && !inc.closed && ++inc.quiet > 3) inc.closed = true;
      draw(); renderStatus(o); renderInc(); renderMetrics(o);
    }
    function draw() {
      const c = $('cv'), g = c.getContext('2d'), W = c.width, H = c.height, pad = 28;
      g.clearRect(0, 0, W, H); g.fillStyle = '#121B33'; g.fillRect(0, 0, W, H);
      g.strokeStyle = '#22305A'; g.lineWidth = 1; g.font = '12px sans-serif'; g.fillStyle = '#7F8DB3';
      [0, 25, 50, 75, 100].forEach((v) => { const y = H - pad - (H - 2 * pad) * v / 100; g.beginPath(); g.moveTo(pad, y); g.lineTo(W - 8, y); g.stroke(); g.fillText(v, 4, y + 4); });
      const dx = (W - pad - 8) / 239;
      hist.forEach((o, i) => { if (o.truth) { g.fillStyle = o.truth === 'flash_crowd' ? 'rgba(255,176,32,.15)' : 'rgba(255,61,113,.28)'; g.fillRect(pad + i * dx - dx / 2, pad, dx, H - 2 * pad); } });
      g.strokeStyle = '#FFB020'; g.setLineDash([6, 5]); const y50 = H - pad - (H - 2 * pad) * 0.5; g.beginPath(); g.moveTo(pad, y50); g.lineTo(W - 8, y50); g.stroke(); g.setLineDash([]);
      g.strokeStyle = '#00F0C8'; g.lineWidth = 2; g.beginPath();
      hist.forEach((o, i) => { const x = pad + i * dx, y = H - pad - (H - 2 * pad) * o.risk / 100; i ? g.lineTo(x, y) : g.moveTo(x, y); }); g.stroke();
      g.fillStyle = '#FFB020'; hist.forEach((o, i) => { if (o.alert) g.fillRect(pad + i * dx - 1.5, 10, 3, 8); });
      g.fillStyle = '#7F8DB3'; g.fillText('last 240 simulated minutes   |   red = real attack   |   amber dots = AegisNet alert', pad, H - 8);
    }
    function renderStatus(o) {
      const el = $('status'), k = o.alert ? o.label : 'normal', col = !o.alert ? '#3DDC97' : (SEV[PLAY[k][0]] || '#FF3D71');
      el.style.borderColor = col;
      el.innerHTML = '<small>' + clock(o.t) + '</small><h2 style="color:' + col + '">' + (o.alert ? nice(k).toUpperCase() : 'ALL NORMAL') + '</h2><div class="risk">risk <b>' + Math.round(o.risk) + '</b>/100</div>' +
        (o.alert && k === 'unknown_anomaly' ? '<p class="note">New pattern: no known attack signature matches. This is the zero-day path.</p>' : '');
    }
    function renderInc() {
      if (!inc) { $('plan').innerHTML = '<p class="note">Launch an attack to see the explanation and the Guardian plan.</p>'; return; }
      const pb = PLAY[inc.label];
      $('plan').innerHTML = '<h3 style="color:' + SEV[pb[0]] + '">[' + pb[0] + '] ' + pb[1] + (inc.closed ? ' (ended)' : '') + '</h3>' +
        '<h4>Why it alerted</h4>' + inc.why.map((w) => '<div class="why"><span>' + w.name + '</span><i style="width:' + Math.round(w.share * 100) + '%"></i><em>' + fmt(w.obs) + ' vs expected ~' + fmt(w.exp) + '</em></div>').join('') +
        '<h4>Guardian ran automatically</h4>' + inc.done.map((a) => '<div class="ok">&#10003; ' + a + '</div>').join('') +
        '<h4>Waiting for a human</h4>' + (inc.pending.length ? inc.pending.map((a) => '<div class="ask">&#9208; ' + a + '</div>').join('') : '<div class="ok">nothing pending</div>');
      $('approve').hidden = !inc.pending.length; $('audit').textContent = audit.slice(0, 8).join('\n');
    }
    function renderMetrics(o) {
      const hot = new Set((inc && !inc.closed ? inc.why : []).map((w) => w.i));
      $('metrics').innerHTML = F.map((f, i) => '<div class="' + (hot.has(i) ? 'hot' : '') + '"><span>' + NAME[i] + '</span><b>' + fmt(o.v[i]) + '</b></div>').join('');
    }
  }
  if (typeof document !== 'undefined') initUI(document);
  API.initUI = initUI;
})(typeof window !== 'undefined' ? window : globalThis);
