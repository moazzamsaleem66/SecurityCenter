'use strict';
// Security Orchestrator: detects the project, runs scanners, normalises/dedupes findings, reconciles with the store.
const fs = require('fs'), path = require('path'), cp = require('child_process'), readline = require('readline');
const { SEV, sha, norm, now } = require('./util');
const { walk, reader, detectTech, git } = require('./walk');
const scanners = require('./scanners');
const { scanDeps, isDepFile } = require('./deps');
const external = require('./external');
const ai = require('./ai');
const store = require('./store');
const { findSecrets, maskLine } = require('./secrets');

const LABELS = { structure: 'Project structure', code: 'Source code', secrets: 'Secret detection', deps: 'Dependencies', network: 'Network security', android: 'Android configuration', ios: 'iOS configuration', flutter: 'Flutter security', config: 'Configuration', external: 'External tools', history: 'Git history', ai: 'AI contextual review' };
const progress = { state: 'idle', steps: [], pct: 0, current: '', error: null };
const busy = new Set();   // roots with a running scan

function dedupe(list) {
  const byFp = new Map(), byLoc = new Map(), out = [];
  for (const f of list) {
    f.fps = [f.fp];
    const loc = f.line > 0 ? `${f.file}|${f.line}|${f.category}` : null;
    let ex = byFp.get(f.fp);
    if (!ex && loc && byLoc.has(loc)) { const c = byLoc.get(loc); if (!f.detectedBy.every(d => c.detectedBy.includes(d))) ex = c; }
    if (!ex) { out.push(f); byFp.set(f.fp, f); if (loc && !byLoc.has(loc)) byLoc.set(loc, f); continue; }
    // merge into ex (prefer the deterministic finding as the base)
    const base = ex.ruleId === 'ai-review' && f.ruleId !== 'ai-review' ? Object.assign(f, { fps: ex.fps }) : ex;
    const other = base === ex ? f : ex;
    base.detectedBy = [...new Set([...ex.detectedBy, ...f.detectedBy])];
    base.fps = [...new Set([...ex.fps, ...f.fps])];
    if (SEV.indexOf(other.severity) > SEV.indexOf(base.severity)) base.severity = other.severity;
    if (base.detectedBy.length > 1) base.confidence = 'high';
    if (base !== ex) { out[out.indexOf(ex)] = base; if (loc) byLoc.set(loc, base); }
    base.fps.forEach(x => byFp.set(x, base));
  }
  return out;
}

function gitHistory(root, known) {
  return new Promise(resolve => {
    const out = [], seen = new Set();
    const p = cp.spawn('git', ['log', '--all', '-p', '--no-color', '-U0', '--diff-filter=AM', '--format=@@@%H'], { cwd: root });
    const rl = readline.createInterface({ input: p.stdout });
    let commit = '', file = '';
    rl.on('line', l => {
      if (l.startsWith('@@@')) { commit = l.slice(3); return; }
      if (l.startsWith('+++ b/')) { file = l.slice(6); return; }
      if (!l.startsWith('+') || l.startsWith('+++') || out.length >= 500 || l.length > 4000) return;
      if (/\.(png|jpe?g|gif|pdf|zip|jar|apk|so|lock)$|package-lock\.json$/i.test(file)) return;
      for (const s of findSecrets(l.slice(1), file)) {
        if (s.publicByDesign) continue;
        const vh = sha(s.value, 12), key = file + vh;
        if (known.has(vh) || seen.has(key)) continue;
        seen.add(key);
        out.push({
          ruleId: `history-${s.id}`, step: 'history', detectedBy: ['Git History Scan'], severity: s.sev === 'critical' ? 'critical' : 'high', category: 'secrets', kind: 'vulnerability', confidence: 'medium',
          cwe: 'CWE-798', owasp: 'M1: Improper Credential Usage', masvs: null, title: `${s.title.replace('Possible ', 'Possible ').replace(' Exposed', '')} found in Git history`,
          file, line: 0, code: maskLine(l.slice(1).trim().slice(0, 200), file), commit: commit.slice(0, 10),
          description: `A value matching this secret pattern was added in commit ${commit.slice(0, 10)} and is no longer in the working tree (or was already reported above). It remains retrievable from repository history.`,
          risk: 'Anyone who can clone the repository can recover the secret from history.', impact: ['Credential exposure'],
          fix: 'Rotate/revoke the credential first. Then remove it from history (git filter-repo or BFG) and force-push if the repository is shared.', env: 'unknown', ctxHash: '', fp: sha(`history|${s.id}|${file}|${vh}`),
        });
      }
    });
    p.on('close', () => resolve(out));
    p.on('error', () => resolve(out));
  });
}

async function scan(root, opts = {}) {
  if (busy.has(root)) throw new Error('A scan is already running');
  busy.add(root);
  store.maintain(root);
  const cfg = store.config(root), startedAt = now(), warnings = [], changedMode = opts.mode === 'changed';
  const keys = ['structure', 'code', 'secrets', 'deps', 'network', 'android', 'ios', 'flutter', 'config'];
  if (!changedMode && !opts.only && opts.external !== false && external.available().length) keys.push('external');
  if (!changedMode && !opts.only && opts.gitHistory) keys.push('history');
  if (opts.ai) keys.push('ai');
  progress.state = 'scanning'; progress.error = null; progress.pct = 0; progress.current = '';
  progress.steps = keys.map(k => ({ key: k, label: LABELS[k], status: 'pending' }));
  const mark = (k, s) => { const st = progress.steps.find(x => x.key === k); st.status = s; progress.current = LABELS[k]; progress.pct = Math.round(progress.steps.filter(x => x.status === 'done' || x.status === 'failed').length / keys.length * 100); };
  try {
    const only = Array.isArray(opts.only) && opts.only.length ? opts.only : null;   // single file / pasted snippet
    const all = only ? only.map(rel => { const abs = path.join(root, rel), st = fs.statSync(abs); return { rel, abs, size: st.size, mtime: st.mtimeMs, binary: false, skipText: false }; }) : walk(root, cfg);
    const read = reader(), tech = detectTech(all), inGit = git.is(root);
    let files = all, partial = only ? new Set(only) : null;
    mark('structure', 'running');
    if (changedMode) {
      if (!inGit) throw new Error('Scan Changed Files needs a git repository');
      const ch = new Set(git.changed(root, opts.base));
      files = all.filter(f => ch.has(f.rel)); partial = new Set(files.map(f => f.rel));
    }
    mark('structure', 'done');
    const raw = [], ran = new Set(['structure']);
    for (const k of keys.slice(1)) {
      mark(k, 'running');
      try {
        if (k === 'deps') raw.push(...await scanDeps(files.filter(f => isDepFile(f.rel)), read, warnings));
        else if (k === 'external') raw.push(...await external.scanExternal(root, warnings));
        else if (k === 'history') raw.push(...await gitHistory(root, new Set(raw.map(f => f.valueHash).filter(Boolean))));
        else if (k === 'ai') {
          const p = ai.provider();
          if (!p) throw new Error('no AI provider available (install the claude CLI or set ANTHROPIC_API_KEY)');
          raw.push(...await ai.reviewFiles(root, files, read, p, warnings));
        } else raw.push(...scanners.scanFiles([k], files, read, root, inGit));
        ran.add(k); mark(k, 'done');
      } catch (e) { warnings.push(`${LABELS[k]} did not complete: ${e.message}`); mark(k, 'failed'); }
    }
    const db = store.open(root);
    const scanRec = store.reconcile(db, dedupe(raw), { ran, partial, only, mode: opts.label || (changedMode ? 'changed' : 'full'), branch: git.branch(root), tech, warnings, startedAt });
    store.save(root, db);
    progress.state = 'completed'; progress.pct = 100;
    return scanRec;
  } catch (e) { progress.state = 'failed'; progress.error = e.message; throw e; }
  finally { busy.delete(root); }
}

// Rescan only what a finding depends on (its file) — never the whole repo.
async function rescanFinding(root, id) {
  const db = store.open(root), f = db.findings[id];
  if (!f) throw new Error('Unknown finding');
  const warnings = [], read = reader();
  let found = false, supported = true, note = '';
  if (['external', 'ai', 'history'].includes(f.step)) supported = false;
  else if (f.step === 'deps') {
    const fl = walk(root, store.config(root)).filter(x => isDepFile(x.rel));
    found = (await scanDeps(fl, read, warnings)).some(c => c.fp === f.fp);
  } else {
    const abs = path.join(root, f.file);
    if (!fs.existsSync(abs)) note = 'File no longer exists';
    else {
      const entry = { rel: f.file, abs, size: fs.statSync(abs).size, binary: false, skipText: false };
      const fps = new Set(scanners.scanFiles([f.step], [entry], read, root, git.is(root)).map(x => x.fp));
      const mine = Object.keys(db.fp).filter(k => db.fp[k] === id);
      found = mine.some(k => fps.has(k));
    }
  }
  if (!supported) return { supported: false, resolved: false, message: 'This finding type cannot be rescanned on its own. Run a project scan (with the relevant option enabled), or confirm manually.' };
  f.lastRescan = now();
  if (found) {
    if (['fix_applied', 'manual_fix_applied', 'rescan_required'].includes(f.status)) f.status = 'open';
    f.statusNote = 'Still detected after rescan'; store.addHistory(f, 'rescan', 'Still detected');
  } else {
    f.status = 'resolved'; f.resolvedAt = now(); f.statusNote = note || 'Not detected in rescan'; store.addHistory(f, 'resolved', f.statusNote);
  }
  store.save(root, db);
  return { supported: true, resolved: !found, message: found ? 'Issue is still detected.' : 'Issue no longer detected — marked Resolved.', finding: f };
}

async function setStatus(root, id, b) {
  const db = store.open(root), f = db.findings[id];
  if (!f) throw new Error('Unknown finding');
  const st = b.status, need = x => { if (!b[x] || !String(b[x]).trim()) throw new Error(`${x} is required`); };
  if (!store.STATUSES.includes(st)) throw new Error('Invalid status');
  if (st === 'false_positive') { need('reason'); f.fpNote = b.reason; f.fpCtx = f.ctxHash || ''; }
  if (st === 'accepted_risk') { need('reason'); f.accept = { reason: b.reason, approvedBy: b.approvedBy || '', expiry: b.expiry || '', ticket: b.ticket || '', comment: b.comment || '', at: now() }; }
  if (st === 'resolved' && !['external', 'ai', 'history'].includes(f.step)) throw new Error('A finding can only become Resolved after a rescan confirms it. Use Rescan Finding.');
  f.status = st; f.statusNote = b.reason || ''; store.addHistory(f, st, b.reason || '');
  store.save(root, db);
  // "I fixed it by hand" -> verify immediately instead of trusting the claim
  if (st === 'manual_fix_applied') return rescanFinding(root, id);
  return { finding: f };
}

// Import findings produced elsewhere (e.g. Claude Code sub-agents) into the store.
function importFindings(root, list, source = 'Claude AI') {
  const db = store.open(root), incoming = ai.toFindings(list, root, source), raw = [];
  const live = Object.values(db.findings).filter(f => f.status !== 'resolved');
  for (const r of incoming) {   // same file+line+category as an existing finding => corroboration, not a new issue
    const ex = live.find(f => f.file === r.file && f.line === r.line && f.category === r.category);
    if (!ex) { raw.push(r); continue; }
    if (!ex.detectedBy.includes(source)) ex.detectedBy.push(source);
    ex.confidence = 'high'; db.fp[r.fp] = ex.id;
    if (SEV.indexOf(r.severity) > SEV.indexOf(ex.severity)) ex.severity = r.severity;
  }
  const rec = store.reconcile(db, dedupe(raw), { ran: new Set(), partial: null, mode: 'import', branch: git.branch(root), tech: [], warnings: [], startedAt: now() });
  store.save(root, db);
  return { imported: raw.length, merged: incoming.length - raw.length, scan: rec };
}

function baseline(root) {
  const db = store.open(root);
  db.baseline = Object.values(db.findings).filter(f => store.ACTIVE.includes(f.status)).map(f => f.id);
  for (const f of Object.values(db.findings)) f.baseline = db.baseline.includes(f.id);
  store.save(root, db);
  return db.baseline.length;
}

function summary(root) {
  const db = store.open(root), list = Object.values(db.findings), last = db.scans[db.scans.length - 1];
  const c = store.counts(list);
  let staleFile = null;
  let state = progress.state === 'scanning' && busy.has(root) ? 'Scanning' : !last ? 'Not Scanned' : progress.state === 'failed' && busy.size === 0 && progress.error ? 'Scan Failed' : 'Scan Completed';
  if (state === 'Scan Completed' && !last.only) {
    const t = Date.parse(last.finishedAt), stale = walk(root, store.config(root)).find(f => f.mtime > t && !f.binary && !f.skipText);
    if (stale) { state = 'Rescan Required'; staleFile = stale.rel; }
  }
  return {
    staleFile, lastOnly: last ? last.only || null : null, project: path.basename(root).startsWith('.secscan-scratch') ? 'Pasted code' : path.basename(root), root, branch: git.branch(root), state, lastScan: last ? last.finishedAt : null, counts: c, score: store.score(c),
    accepted: list.filter(f => f.status === 'accepted_risk').length, tech: last ? last.tech : [], warnings: last ? last.warnings : [],
    ai: (p => p ? p.name : null)(ai.provider()), externalTools: external.available(), baselineSize: db.baseline.length,
  };
}

module.exports = { scan, rescanFinding, setStatus, importFindings, baseline, summary, progress, dedupe, LABELS };
