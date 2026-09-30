'use strict';
const fs = require('fs'), path = require('path');
const { SEV, now } = require('./util');

const ACTIVE = ['open', 'reviewing', 'ai_fix_proposed', 'fix_applied', 'manual_fix_applied', 'rescan_required'];
const STATUSES = [...ACTIVE, 'resolved', 'false_positive', 'accepted_risk', 'ignored'];
const dir = root => path.join(root, '.secscan');

function config(root) {
  try { return JSON.parse(fs.readFileSync(path.join(dir(root), 'config.json'), 'utf8')); } catch { return {}; }
}

function open(root) {
  try { return JSON.parse(fs.readFileSync(path.join(dir(root), 'db.json'), 'utf8')); }
  catch { return { version: 1, next: 1, findings: {}, fp: {}, scans: [], baseline: [] }; }
}
function save(root, db) {
  fs.mkdirSync(dir(root), { recursive: true });
  const gi = path.join(dir(root), '.gitignore');   // "*" inside .secscan/ makes git ignore the whole folder — scan data never gets committed by accident
  if (!fs.existsSync(gi)) fs.writeFileSync(gi, '*\n');
  const f = path.join(dir(root), 'db.json'), tmp = f + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 1));
  fs.renameSync(tmp, f);
}

const counts = list => { const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }; for (const f of list) if (ACTIVE.includes(f.status)) c[f.severity]++; return c; };
function score(c) {
  // diminishing curve: 0 penalty = 100, never reaches 0 from volume alone; a critical always caps it in the red
  const penalty = c.critical * 15 + c.high * 7 + c.medium * 2 + c.low * 0.5;
  const s = Math.round(100 / (1 + penalty / 40));
  return c.critical ? Math.min(s, 69) : s;
}

function reconcile(db, cur, o) {
  const t = now(), day = t.slice(0, 10).replace(/-/g, '');
  const seq = db.scans.filter(s => s.id.startsWith(`scan-${day}`)).length + 1;
  const scanId = `scan-${day}-${String(seq).padStart(3, '0')}`;
  const prev = db.scans[db.scans.length - 1], prevIds = new Set(prev ? prev.items.map(i => i.id) : []);
  const seen = new Set(), diff = { new: [], resolved: [], unchanged: [], reopened: [] };

  for (const n of cur) {
    let id = (n.fps || [n.fp]).map(x => db.fp[x]).find(Boolean), f = id && db.findings[id];
    if (!f) {
      id = `SEC-${String(db.next++).padStart(4, '0')}`;
      f = db.findings[id] = { id, status: 'open', firstSeen: t, firstScan: scanId, history: [], chat: [] };
      diff.new.push(id);
    } else if (f.status === 'resolved') {
      f.status = 'open'; f.reopened = (f.reopened || 0) + 1; f.resolvedAt = null; diff.reopened.push(id);
      f.history.push({ t, e: 'reopened', note: 'Detected again in scan' });
    } else diff.unchanged.push(id);
    for (const x of n.fps || [n.fp]) db.fp[x] = id;
    seen.add(id);
    // carry user state; refresh detection data
    const keep = { id: f.id, status: f.status, firstSeen: f.firstSeen, firstScan: f.firstScan, history: f.history, chat: f.chat, reopened: f.reopened, accept: f.accept, fpNote: f.fpNote, fpCtx: f.fpCtx, proposal: f.proposal, applied: f.applied, verification: f.verification, statusNote: f.statusNote };
    Object.assign(f, n, keep);
    f.lastSeen = t; f.lastScan = scanId;
    if (f.status === 'false_positive' && f.fpCtx && n.ctxHash && n.ctxHash !== f.fpCtx) { f.status = 'open'; f.statusNote = 'Code changed since it was marked false positive'; f.history.push({ t, e: 'reopened', note: f.statusNote }); }
    if (f.status === 'accepted_risk' && f.accept && f.accept.expiry && Date.parse(f.accept.expiry) < Date.now()) { f.status = 'open'; f.riskExpired = true; f.statusNote = 'Accepted-risk review date passed'; f.history.push({ t, e: 'reopened', note: f.statusNote }); }
    if (['fix_applied', 'manual_fix_applied', 'rescan_required'].includes(f.status)) { f.status = 'open'; f.statusNote = 'Still detected after fix/rescan'; }
  }

  for (const f of Object.values(db.findings)) {
    if (seen.has(f.id) || f.status === 'resolved') continue;
    const covered = o.ran.has(f.step) && f.step !== 'history' && (!o.partial || o.partial.has(f.file));
    if (covered) { f.status = 'resolved'; f.resolvedAt = t; f.statusNote = 'Not detected in rescan'; f.history.push({ t, e: 'resolved', note: 'Confirmed by scan ' + scanId }); diff.resolved.push(f.id); }
    else if (prevIds.has(f.id)) diff.unchanged.push(f.id);
  }
  for (const f of Object.values(db.findings)) f.baseline = db.baseline.includes(f.id);

  const live = Object.values(db.findings).filter(f => f.status !== 'resolved');
  const scan = {
    id: scanId, startedAt: o.startedAt, finishedAt: t, mode: o.mode, only: o.only || null, branch: o.branch, tech: o.tech, warnings: o.warnings, steps: [...o.ran],
    counts: counts(live), total: live.filter(f => ACTIVE.includes(f.status)).length,
    items: live.map(f => ({ id: f.id, s: f.severity, st: f.status })),
    diff: Object.fromEntries(Object.entries(diff).map(([k, v]) => [k, [...new Set(v)]])),
  };
  scan.score = score(scan.counts);
  db.scans.push(scan);
  return scan;
}

function compare(db, a, b) {
  const A = db.scans.find(s => s.id === a), B = db.scans.find(s => s.id === b);
  if (!A || !B) return null;
  const ia = new Set(A.items.map(i => i.id)), ib = new Set(B.items.map(i => i.id));
  return { a: { id: A.id, counts: A.counts }, b: { id: B.id, counts: B.counts },
    resolved: [...ia].filter(x => !ib.has(x)), new: [...ib].filter(x => !ia.has(x)), unchanged: [...ib].filter(x => ia.has(x)) };
}

// ---- retention: history is kept `retentionDays` (default 7), then removed ----
const DAY = 864e5;
function prune(root, db, days = 7) {
  const cut = Date.now() - days * DAY; let n = 0;
  const last = db.scans[db.scans.length - 1];   // the newest scan is always kept: the dashboard and "new vs fixed" are based on it
  const kept = db.scans.filter(s => s === last || Date.parse(s.finishedAt) >= cut);
  n += db.scans.length - kept.length; db.scans = kept;
  const drop = id => { delete db.findings[id]; for (const k of Object.keys(db.fp)) if (db.fp[k] === id) delete db.fp[k]; n++; };
  for (const f of Object.values(db.findings)) if (f.status === 'resolved' && f.resolvedAt && Date.parse(f.resolvedAt) < cut) drop(f.id);
  const rmOld = (base, test, onRemove) => { try { for (const e of fs.readdirSync(base)) { const p = path.join(base, e); if (test(e) && fs.statSync(p).mtimeMs < cut) { fs.rmSync(p, { recursive: true, force: true }); onRemove(e); n++; } } } catch { /* none */ } };
  rmOld(path.join(dir(root), 'backups'), () => true, e => { for (const f of Object.values(db.findings)) if (f.applied && f.applied.backup.endsWith(e)) f.applied = null; });
  if (path.basename(root).startsWith('.secscan-scratch')) rmOld(root, e => e.startsWith('paste-'), e => { for (const f of Object.values(db.findings)) if (f.file.startsWith(e + '/')) drop(f.id); });
  return n;
}
function maintain(root) {
  const db = open(root), n = prune(root, db, config(root).retentionDays || 7);
  if (n) save(root, db);
  return n;
}
function deleteScan(root, id) {
  const db = open(root), i = db.scans.findIndex(s => s.id === id);
  if (i < 0) throw new Error('Unknown scan');
  if (i === db.scans.length - 1) throw new Error('This is the latest scan — the dashboard is based on it. Run a new scan first, or use "Clear all history".');
  db.scans.splice(i, 1); save(root, db);
}
function clearAll(root) {   // wipes findings + history + AI-fix backups for this project (config.json is kept)
  for (const f of ['db.json', 'db.json.tmp']) try { fs.rmSync(path.join(dir(root), f), { force: true }); } catch { /* none */ }
  try { fs.rmSync(path.join(dir(root), 'backups'), { recursive: true, force: true }); } catch { /* none */ }
}

function addHistory(f, e, note) { f.history.push({ t: now(), e, note: note || '' }); }

module.exports = { open, save, config, reconcile, compare, counts, score, addHistory, prune, maintain, deleteScan, clearAll, ACTIVE, STATUSES, SEV, dir };
