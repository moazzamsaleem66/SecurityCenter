'use strict';
// AI fix lifecycle: propose -> show diff -> developer approves -> backup -> apply -> rescan -> (optional) build check -> undo.
// Nothing is written to the project until apply() is called with an explicit approval of the exact proposal.
const fs = require('fs'), path = require('path');
const { sha, now, exec } = require('./util');
const { maskLine } = require('./secrets');
const ai = require('./ai');
const store = require('./store');
const engine = require('./engine');

const inside = (root, rel) => { const p = path.resolve(root, rel); return p.startsWith(path.resolve(root) + path.sep) ? p : null; };

function unifiedDiff(rel, before, after, ctx = 3) {
  const a = before.split('\n'), b = after.split('\n');
  let s = 0; while (s < a.length && s < b.length && a[s] === b[s]) s++;
  let ea = a.length - 1, eb = b.length - 1; while (ea >= s && eb >= s && a[ea] === b[eb]) { ea--; eb--; }
  const from = Math.max(0, s - ctx), toA = Math.min(a.length - 1, ea + ctx), toB = Math.min(b.length - 1, eb + ctx);
  const out = [`--- a/${rel}`, `+++ b/${rel}`, `@@ -${from + 1},${toA - from + 1} +${from + 1},${toB - from + 1} @@`];
  for (let i = from; i < s; i++) out.push(' ' + a[i]);
  for (let i = s; i <= ea; i++) out.push('-' + a[i]);
  for (let i = s; i <= eb; i++) out.push('+' + b[i]);
  for (let i = ea + 1; i <= toA; i++) out.push(' ' + a[i]);
  return out.join('\n');
}

async function propose(root, id, mode = 'recommended') {
  const p = ai.provider();
  if (!p) throw new Error('No AI provider available (install the claude CLI or set ANTHROPIC_API_KEY).');
  const db = store.open(root), f = db.findings[id];
  if (!f) throw new Error('Unknown finding');
  const last = db.scans[db.scans.length - 1];
  const raw = ai.parseJson(await p.ask(ai.fixPrompt(root, f, mode, last ? last.tech : []), { cwd: root }), '{');
  const files = {}, edits = [];
  for (const e of raw.edits || []) {
    const abs = inside(root, e.file || '');
    if (!abs || !fs.existsSync(abs)) throw new Error(`AI proposed an edit outside the project or to a missing file: ${e.file}`);
    const cur = files[e.file] ?? (files[e.file] = fs.readFileSync(abs, 'utf8'));
    if (!e.old || cur.split(e.old).length !== 2) throw new Error(`AI edit for ${e.file} did not match the file exactly once — regenerate.`);
    files[e.file] = cur.replace(e.old, () => e.new ?? '');
    edits.push({ file: e.file, old: e.old, new: e.new ?? '' });
  }
  const diff = Object.keys(files).map(rel => unifiedDiff(rel, fs.readFileSync(path.join(root, rel), 'utf8'), files[rel])).join('\n\n');
  f.proposal = { id: sha(now() + diff, 12), mode, at: now(), summary: raw.summary || '', sideEffects: raw.sideEffects || '', manualSteps: raw.manualSteps || '', edits, diff: maskLine(diff), sensitive: /authentic|cert|crypto|network|authoriz|token|secret/i.test(f.category + f.title) };
  if (f.status === 'open') f.status = 'ai_fix_proposed';
  store.addHistory(f, 'ai_fix_proposed', `${mode} fix`);
  store.save(root, db);
  const { edits: _e, ...pub } = f.proposal;
  return pub;
}

async function apply(root, id, { proposalId, approve, verifyBuild }) {
  if (approve !== true) throw new Error('Developer approval is required to apply a fix.');
  const db = store.open(root), f = db.findings[id];
  if (!f || !f.proposal || f.proposal.id !== proposalId) throw new Error('Proposal not found or out of date — generate the fix again.');
  const byFile = {};
  for (const e of f.proposal.edits) {
    const abs = inside(root, e.file); if (!abs) throw new Error('Path outside project');
    const cur = byFile[e.file] ?? (byFile[e.file] = fs.readFileSync(abs, 'utf8'));
    if (cur.split(e.old).length !== 2) throw new Error(`${e.file} changed since the fix was proposed — regenerate.`);
    byFile[e.file] = cur.replace(e.old, () => e.new);
  }
  // backup first (revertible even without git)
  const bdir = path.join(store.dir(root), 'backups', `${id}-${Date.now()}`), files = [];
  for (const rel of Object.keys(byFile)) {
    const abs = path.join(root, rel), dst = path.join(bdir, rel);
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    const before = fs.readFileSync(abs); fs.writeFileSync(dst, before);
    fs.writeFileSync(abs, byFile[rel]);
    files.push({ rel, before: sha(before), after: sha(byFile[rel]) });
  }
  f.applied = { at: now(), backup: path.relative(root, bdir), files };
  f.status = 'fix_applied'; store.addHistory(f, 'fix_applied', `${files.length} file(s) changed`);
  store.save(root, db);
  const res = await engine.rescanFinding(root, id);           // only a rescan can resolve it
  const verification = { security: res.resolved ? 'resolved' : 'still_detected', build: 'skipped', buildOutput: '' };
  if (verifyBuild) Object.assign(verification, await buildCheck(root));
  const db2 = store.open(root), f2 = db2.findings[id];
  f2.verification = { ...verification, at: now() };
  store.save(root, db2);
  return { rescan: res, verification: f2.verification, finding: f2 };
}

function undo(root, id, force) {
  const db = store.open(root), f = db.findings[id];
  if (!f || !f.applied) throw new Error('Nothing to undo');
  for (const x of f.applied.files) {
    const abs = path.join(root, x.rel);
    if (!force && fs.existsSync(abs) && sha(fs.readFileSync(abs)) !== x.after) throw new Error(`${x.rel} was modified after the AI fix; undo would discard those edits (retry with force).`);
  }
  for (const x of f.applied.files) fs.copyFileSync(path.join(root, f.applied.backup, x.rel), path.join(root, x.rel));
  f.applied = null; f.verification = null; f.status = 'open'; f.statusNote = 'AI fix undone';
  store.addHistory(f, 'undo', 'AI fix reverted'); store.save(root, db);
  return f;
}

// Detect & run a build/analyze command. Separate from the security result on purpose.
function buildCommand(root) {
  const cfg = store.config(root);
  if (cfg.build) return cfg.build;
  const has = f => fs.existsSync(path.join(root, f));
  if (has('pubspec.yaml')) return 'flutter analyze';
  if (has('gradlew')) return './gradlew lintDebug testDebugUnitTest --console=plain';
  if (has('package.json')) return 'npm test --silent';
  return null;
}
async function buildCheck(root) {
  const cmd = buildCommand(root);
  if (!cmd) return { build: 'skipped', buildOutput: 'No build command detected (set "build" in .secscan/config.json).' };
  const r = await exec(cmd, [], { cwd: root, shell: true, timeout: 900000 });
  return { build: r.ok ? 'passed' : 'failed', buildCommand: cmd, buildOutput: (r.out + r.err).slice(-3000) };
}

module.exports = { propose, apply, undo, buildCheck, unifiedDiff };
