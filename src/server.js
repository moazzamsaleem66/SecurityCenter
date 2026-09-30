'use strict';
// Local HTTP API + static UI. Binds to 127.0.0.1 only; every API call needs the per-run token
// (prevents other websites from driving the scanner via the browser).
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto'), cp = require('child_process');
const engine = require('./engine'), store = require('./store'), ai = require('./ai'), fix = require('./fix'), report = require('./report');
const { maskLine } = require('./secrets');

const os = require('os');
const { exec } = require('./util');
const LAST = path.join(os.homedir(), '.secscan-last.json');
const recents = () => { try { return (JSON.parse(fs.readFileSync(LAST, 'utf8')).recent || []).filter(p => fs.existsSync(p)); } catch { return []; } };
const remember = root => { const r = [root, ...recents().filter(x => x !== root)].slice(0, 12); try { fs.writeFileSync(LAST, JSON.stringify({ root, recent: r })); } catch { /* ignore */ } };
const lastProject = () => { try { const p = JSON.parse(fs.readFileSync(LAST, 'utf8')).root; return fs.statSync(p).isDirectory() ? p : null; } catch { return null; } };

// native folder/file picker (macOS / Windows / Linux-zenity); resolves to a path or null if cancelled
async function pick(kind = 'folder') {
  const file = kind === 'file';
  const r = process.platform === 'darwin' ? await exec('osascript', ['-e', `POSIX path of (choose ${file ? 'file' : 'folder'} with prompt "Select the ${file ? 'file' : 'project folder'} to scan")`], { timeout: 300000 })
    : process.platform === 'win32' ? await exec('powershell', ['-NoProfile', '-Command', file ? 'Add-Type -AssemblyName System.Windows.Forms; $d=New-Object System.Windows.Forms.OpenFileDialog; if($d.ShowDialog() -eq "OK"){$d.FileName}' : 'Add-Type -AssemblyName System.Windows.Forms; $d=New-Object System.Windows.Forms.FolderBrowserDialog; if($d.ShowDialog() -eq "OK"){$d.SelectedPath}'], { timeout: 300000 })
      : await exec('zenity', file ? ['--file-selection'] : ['--file-selection', '--directory'], { timeout: 300000 });
  const p = r.out.trim().replace(/\/$/, '');
  if (!r.ok && !p) { if (/not found|ENOENT/i.test(r.err)) throw new Error(`No ${kind} picker available on this system — type the path instead.`); return null; }
  return p || null;
}
const SNIP = { dart: 'snippet.dart', kotlin: 'Snippet.kt', java: 'Snippet.java', swift: 'Snippet.swift', js: 'snippet.js', ts: 'snippet.ts', python: 'snippet.py', manifest: 'AndroidManifest.xml', gradle: 'build.gradle', gradlekts: 'build.gradle.kts', nsc: 'res/xml/network_security_config.xml', plist: 'Info.plist', pubspec: 'pubspec.yaml', rules: 'firestore.rules', docker: 'Dockerfile', props: 'app.properties' };

function start(root, port = 4317) {
  const token = crypto.randomBytes(18).toString('hex');
  const indexHtml = () => fs.readFileSync(path.join(__dirname, '..', 'ui', 'index.html'), 'utf8').replace('__TOKEN__', token);
  let sumCache = { t: 0, v: null };
  const summary = () => { if (Date.now() - sumCache.t > 4000 || engine.progress.state === 'scanning') sumCache = { t: Date.now(), v: engine.summary(root) }; return sumCache.v; };
  const invalidate = () => { sumCache.t = 0; };

  const ctxLines = (f, r = 8) => {
    if (!f.line) return null;
    try {
      const L = fs.readFileSync(path.join(root, f.file), 'utf8').split('\n'), a = Math.max(0, f.line - 1 - r), b = Math.min(L.length, f.line + r);
      return { start: a + 1, hit: f.line, lines: L.slice(a, b).map(l => maskLine(l.slice(0, 300), f.file)) };
    } catch { return null; }
  };

  const routes = {
    'GET /api/state': () => summary(),
    'GET /api/progress': () => engine.progress,
    'GET /api/findings': () => Object.values(store.open(root).findings).map(report.pub).map(f => { const { history, ...r } = f; return r; }),
    'GET /api/scans': () => { store.maintain(root); return store.open(root).scans.map(({ items, ...s }) => s).reverse(); },
    'GET /api/compare': (q) => store.compare(store.open(root), q.a, q.b),
    'POST /api/scan': async b => { const p = engine.scan(root, b); p.catch(() => {}); invalidate(); return { started: true }; },
    'GET /api/projects': () => recents().map(p => { const sc = store.open(p).scans.slice(-1)[0]; return { root: p, name: path.basename(p), current: p === root, last: sc ? { id: sc.id, at: sc.finishedAt, counts: sc.counts, total: sc.total, score: sc.score } : null }; }),
    'POST /api/scan-file': async b => {
      if (engine.progress.state === 'scanning') throw new Error('Wait for the running scan to finish');
      const f = b.path ? path.resolve(String(b.path).replace(/^~(?=$|\/)/, os.homedir())) : await pick('file');
      if (!f) return { cancelled: true };
      if (!fs.existsSync(f) || !fs.statSync(f).isFile()) throw new Error('Not a file: ' + f);
      root = path.dirname(f); remember(root); invalidate();
      const only = [path.basename(f)];
      engine.scan(root, { only, label: 'file', ai: b.ai }).catch(() => {}); invalidate();
      return { root, file: only[0] };
    },
    'POST /api/scan-snippet': async b => {
      if (engine.progress.state === 'scanning') throw new Error('Wait for the running scan to finish');
      const code = String(b.code || ''), name = SNIP[b.lang];
      if (!code.trim()) throw new Error('Paste some code first');
      if (!name) throw new Error('Choose what kind of code this is');
      if (code.length > 500000) throw new Error('Snippet too large (500 KB max)');
      const base = path.join(os.homedir(), '.secscan-scratch'), rel = `paste-${new Date().toISOString().replace(/[:.]/g, '-')}/${name}`;
      fs.mkdirSync(path.dirname(path.join(base, rel)), { recursive: true }); fs.writeFileSync(path.join(base, rel), code);
      root = base; invalidate();
      engine.scan(root, { only: [rel], label: 'snippet', ai: b.ai }).catch(() => {}); invalidate();
      return { root, file: rel };
    },
    'POST /api/project': async b => {
      let p = b.path ? path.resolve(String(b.path).replace(/^~(?=$|\/)/, os.homedir())) : await pick('folder');
      if (!p) return { cancelled: true, root };
      if (!fs.existsSync(p) || !fs.statSync(p).isDirectory()) throw new Error('Not a folder: ' + p);
      if (engine.progress.state === 'scanning') throw new Error('Wait for the running scan to finish');
      root = p; engine.progress.state = 'idle'; engine.progress.error = null; invalidate();
      remember(root);
      return { root };
    },
    'POST /api/scan-delete': b => { store.deleteScan(root, String(b.id)); invalidate(); return { ok: true }; },
    'POST /api/history-clear': () => { if (engine.progress.state === 'scanning') throw new Error('Wait for the running scan to finish'); store.clearAll(root); engine.progress.state = 'idle'; invalidate(); return { ok: true }; },
    'POST /api/baseline': () => ({ baseline: engine.baseline(root) }),
    'POST /api/import': b => engine.importFindings(root, b.findings, b.source),
  };

  const findingRoute = async (m, id, act, b, q) => {
    const db = store.open(root), f = db.findings[id];
    if (!f) return [404, { error: 'Unknown finding' }];
    if (m === 'GET' && !act) { const { chat, proposal, fps, applied, ...r } = f; r.proposal = proposal ? { ...proposal, edits: undefined } : null; r.context = ctxLines(f); r.canUndo = !!applied; r.chat = chat; return [200, r]; }
    if (m !== 'POST') return [405, { error: 'Method not allowed' }];
    invalidate();
    if (act === 'status') return [200, await engine.setStatus(root, id, b)];
    if (act === 'rescan') return [200, await engine.rescanFinding(root, id)];
    if (act === 'ask') {
      const p = ai.provider(); if (!p) return [400, { error: 'No AI provider available. Install the claude CLI or set ANTHROPIC_API_KEY.' }];
      const last = db.scans[db.scans.length - 1], q2 = String(b.question || 'Explain this issue.').slice(0, 2000);
      const text = maskLine(await p.ask(ai.askPrompt(root, f, q2, last ? last.tech : []), { cwd: root }));
      f.chat.push({ role: 'developer', text: q2 }, { role: 'ai', text }); store.save(root, db);
      return [200, { answer: text }];
    }
    if (act === 'fix') return [200, await fix.propose(root, id, b.mode)];
    if (act === 'apply') return [200, await fix.apply(root, id, b)];
    if (act === 'undo') return [200, fix.undo(root, id, b.force)];
    if (act === 'cancel-fix') { f.proposal = null; if (f.status === 'ai_fix_proposed') f.status = 'open'; store.save(root, db); return [200, { ok: true }]; }
    if (act === 'open') {
      const ed = process.env.SECSCAN_EDITOR || 'code';
      const abs = path.join(root, f.file);
      const args = ed === 'code' || ed === 'cursor' ? ['-g', `${abs}:${f.line || 1}`] : [abs];
      try { cp.spawn(ed, args, { detached: true, stdio: 'ignore' }).on('error', () => {}).unref(); } catch { /* ignore */ }
      return [200, { opened: abs, line: f.line }];
    }
    return [404, { error: 'Unknown action' }];
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x'), send = (code, body, type = 'application/json') => { res.writeHead(code, { 'content-type': type + '; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }); res.end(typeof body === 'string' ? body : JSON.stringify(body)); };
    if (!/^(localhost|127\.0\.0\.1)(:\d+)?$/.test(req.headers.host || '')) return send(403, { error: 'bad host' });
    if (url.pathname === '/') return send(200, indexHtml(), 'text/html');
    const am = url.pathname.match(/^\/assets\/([\w-]+\.png)$/);
    if (am) { try { res.writeHead(200, { 'content-type': 'image/png', 'cache-control': 'public, max-age=3600' }); return res.end(fs.readFileSync(path.join(__dirname, '..', 'ui', 'assets', am[1]))); } catch { return send(404, { error: 'not found' }); } }
    if (!url.pathname.startsWith('/api/')) return send(404, { error: 'not found' });
    if (req.headers['x-secscan-token'] !== token && url.searchParams.get('token') !== token) return send(403, { error: 'bad token' });
    let body = '';
    for await (const c of req) { body += c; if (body.length > 2e6) return send(413, { error: 'too large' }); }
    let b = {}; try { b = body ? JSON.parse(body) : {}; } catch { return send(400, { error: 'bad json' }); }
    const q = Object.fromEntries(url.searchParams);
    try {
      if (url.pathname === '/api/export') {
        const fmt = q.fmt || 'json', t = { json: 'application/json', csv: 'text/csv', html: 'text/html' }[fmt];
        if (!t) return send(400, { error: 'fmt must be json|csv|html' });
        res.setHeader('content-disposition', `attachment; filename="security-report.${fmt}"`);
        return send(200, report[fmt](root), t);
      }
      const sm = url.pathname.match(/^\/api\/scan\/(scan-[\w-]+)$/);
      if (sm) {
        const db = store.open(root), sc = db.scans.find(x => x.id === sm[1]);
        if (!sc) return send(404, { error: 'Unknown scan' });
        const j = (id, sev, st) => { const f = db.findings[id]; return f ? { id, severity: sev || f.severity, status: st || f.status, title: f.title, file: f.file, line: f.line, category: f.category } : null; };
        const { items, ...meta } = sc, isNew = new Set(sc.diff.new);
        return send(200, { scan: meta, present: items.map(i => j(i.id, i.s, i.st)).filter(Boolean).map(x => ({ ...x, isNew: isNew.has(x.id) })), resolved: sc.diff.resolved.map(id => j(id)).filter(Boolean) });
      }
      const m = url.pathname.match(/^\/api\/finding\/(SEC-\d+)(?:\/(\w[\w-]*))?$/);
      if (m) { const [code, out] = await findingRoute(req.method, m[1], m[2], b, q); return send(code, out); }
      const h = routes[`${req.method} ${url.pathname}`];
      if (!h) return send(404, { error: 'not found' });
      return send(200, await h(req.method === 'GET' ? q : b));
    } catch (e) { return send(500, { error: e.message }); }
  });
  store.maintain(root); setInterval(() => { try { store.maintain(root); } catch { /* ignore */ } }, 3600 * 1000).unref();   // also prune hourly while running
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve({ server, url: `http://localhost:${server.address().port}/`, token }));
  });
}

module.exports = { start, lastProject };
