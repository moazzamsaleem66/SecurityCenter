'use strict';
// Self-check: builds a throwaway project with planted issues and asserts the whole lifecycle.
// Run: node test/selftest.js        (fake secrets are assembled at runtime so no real-looking key is committed)
const fs = require('fs'), os = require('os'), path = require('path'), assert = require('assert');
const engine = require('../src/engine'), store = require('../src/store'), fix = require('../src/fix'), report = require('../src/report');

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secscan-'));
const w = (rel, txt) => { const p = path.join(root, rel); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, txt); };
const STRIPE = 'sk_' + 'live_' + 'Ab12Cd34Ef56Gh78Ij90Kl12';
const GHP = 'gh' + 'p_' + 'aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0hJ3kL6';

w('pubspec.yaml', 'name: demo\n');
w('lib/network/network_manager.dart', `import 'dart:io';
void init(HttpClient c) {
  c.badCertificateCallback = (cert, host, port) => true;
  final url = 'http://api.example-bank.io/v1';
}
`);
w('lib/config/constants.dart', `const stripeKey = "${STRIPE}";\nconst label = "password_hint";\nconst pw = "changeme";\n`);
w('lib/services/session_service.dart', `void f(String token, SharedPreferences prefs) {\n  print("AppCheckToken: $token");\n  prefs.setString('auth_token', token);\n  if (kDebugMode) { print("debug token $token"); }\n  final d = md5.convert(utf8.encode(password));\n\n\n  final c = md5.convert(utf8.encode(file));\n}\n`);
w('android/app/src/main/AndroidManifest.xml', `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="true" android:debuggable="true" android:usesCleartextTraffic="true">
    <activity android:name=".Main" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>
    <service android:name=".Sync" android:exported="true"/>
    <receiver android:name=".Boot"><intent-filter><action android:name="x"/></intent-filter></receiver>
  </application>
</manifest>
`);
w('android/app/build.gradle', `android { buildTypes { release { signingConfig signingConfigs.debug\n minifyEnabled false } } }\nsigningConfigs { release { storePassword 'Hunter2Hunter2!' } }\n`);
w('firestore.rules', `rules_version = '2';\nservice cloud.firestore { match /databases/{d}/documents { match /{doc=**} { allow read, write: if true; } } }\n`);
w('test/foo_test.dart', `final k = "${STRIPE}";\nvoid t(){ c.badCertificateCallback = (a,b,c)=>true; }\n`);
w('.env', `API_TOKEN=${GHP}\n`);
w('key.properties', 'storePassword=Sup3rS3cretPass\n');
w('build/generated.dart', `const k = "${STRIPE}";\n`);

(async () => {
  const s1 = await engine.scan(root, { external: false });
  const db = store.open(root), all = Object.values(db.findings);
  const has = (ruleId, file) => all.find(f => f.ruleId === ruleId && (!file || f.file === file));
  const dump = JSON.stringify(db);

  // detection
  assert(has('net-dart-bad-cert', 'lib/network/network_manager.dart').severity === 'high', 'bad cert high');
  assert(has('net-http-url', 'lib/network/network_manager.dart'), 'http url');
  assert(has('secret-stripe-live-key', 'lib/config/constants.dart').severity === 'critical', 'stripe critical');
  assert(has('log-sensitive', 'lib/services/session_service.dart'), 'sensitive log');
  assert(has('fl-sharedprefs-sensitive'), 'sharedprefs');
  assert(all.filter(f => f.ruleId === 'crypto-weak-hash').length === 1, 'md5 only flagged in security context');
  assert(has('and-debuggable') && has('and-allowbackup') && has('and-cleartext'), 'manifest flags');
  assert(has('and-exported') && all.some(f => f.title.startsWith('Exported service')), 'exported service');
  assert(all.some(f => f.title.includes('not declared')), 'implicit export');
  assert(!all.some(f => /Exported activity/.test(f.title)), 'launcher activity not flagged');
  assert(has('and-release-debug-signing'), 'debug signing');
  assert(all.some(f => f.ruleId === 'secret-hardcoded-credential' && f.file.endsWith('build.gradle')), 'gradle store password');
  assert(has('cfg-rules-open').severity === 'critical', 'open firestore rules');
  assert(has('secret-file', '.env'), '.env file');
  // noise control
  assert(!all.some(f => f.file.startsWith('build/')), 'build/ excluded');
  assert(!all.some(f => f.file === 'lib/config/constants.dart' && /password|changeme/i.test(f.code) && f.ruleId.startsWith('secret-hard')), 'placeholder/i18n not flagged');
  const tf = all.filter(f => f.file === 'test/foo_test.dart');
  assert(tf.every(f => f.category === 'secrets') && tf.every(f => f.severity !== 'critical'), 'test files: secrets only, downgraded');
  const dbg = all.find(f => f.ruleId === 'log-sensitive' && /debug token/.test(f.code));
  assert(dbg && dbg.env === 'debug' && dbg.severity === 'medium', 'kDebugMode downgrade');
  // secrets never stored/exported in full
  for (const secret of [STRIPE, GHP, 'Hunter2Hunter2!', 'Sup3rS3cretPass']) { assert(!dump.includes(secret), 'secret leaked in db'); assert(!report.html(root).includes(secret) && !report.csv(root).includes(secret), 'secret leaked in report'); }
  assert(has('secret-stripe-live-key').code.includes('*'), 'masked');
  // stable IDs + scan diff
  const ids1 = Object.fromEntries(all.map(f => [f.fp, f.id]));
  const s2 = await engine.scan(root, { external: false });
  const db2 = store.open(root);
  assert(Object.values(db2.findings).every(f => ids1[f.fp] === f.id || !ids1[f.fp]), 'IDs stable');
  assert(s2.diff.new.length === 0 && s2.diff.resolved.length === 0, 'unchanged rescan has no diff');

  // manual fix must be verified by rescan, never trusted
  const bad = Object.values(db2.findings).find(f => f.ruleId === 'net-dart-bad-cert');
  let r = await engine.setStatus(root, bad.id, { status: 'manual_fix_applied' });
  assert(!r.resolved && store.open(root).findings[bad.id].status === 'open', 'claiming fixed does not resolve');
  await assert.rejects(engine.setStatus(root, bad.id, { status: 'resolved' }), /rescan/i);
  await assert.rejects(engine.setStatus(root, bad.id, { status: 'false_positive' }), /reason/);
  await assert.rejects(engine.setStatus(root, bad.id, { status: 'accepted_risk', reason: ' ' }), /reason/);

  // AI-style fix: propose (injected) -> apply needs approval -> rescan resolves -> undo restores
  const file = path.join(root, 'lib/network/network_manager.dart'), orig = fs.readFileSync(file, 'utf8');
  const db3 = store.open(root), f3 = db3.findings[bad.id];
  f3.proposal = { id: 'p1', edits: [{ file: 'lib/network/network_manager.dart', old: '  c.badCertificateCallback = (cert, host, port) => true;\n', new: '' }], diff: fix.unifiedDiff('x', 'a\nb', 'a\nc') };
  store.save(root, db3);
  await assert.rejects(fix.apply(root, bad.id, { proposalId: 'p1' }), /approval/);
  assert.strictEqual(fs.readFileSync(file, 'utf8'), orig, 'nothing written without approval');
  const ap = await fix.apply(root, bad.id, { proposalId: 'p1', approve: true });
  assert(ap.rescan.resolved && ap.verification.security === 'resolved' && store.open(root).findings[bad.id].status === 'resolved', 'rescan resolves after fix');
  assert(!fs.readFileSync(file, 'utf8').includes('badCertificateCallback'), 'fix written');
  fix.undo(root, bad.id);
  assert.strictEqual(fs.readFileSync(file, 'utf8'), orig, 'undo restores file');
  assert.strictEqual(store.open(root).findings[bad.id].status, 'open', 'undo reopens');

  // false positive persists until the code changes
  const stripe = Object.values(store.open(root).findings).find(f => f.ruleId === 'secret-stripe-live-key' && f.file === 'lib/config/constants.dart');
  await engine.setStatus(root, stripe.id, { status: 'false_positive', reason: 'test fixture' });
  await engine.scan(root, { external: false });
  assert.strictEqual(store.open(root).findings[stripe.id].status, 'false_positive', 'FP remembered');
  fs.appendFileSync(path.join(root, 'lib/config/constants.dart'), '// edit\n');
  fs.writeFileSync(path.join(root, 'lib/config/constants.dart'), fs.readFileSync(path.join(root, 'lib/config/constants.dart'), 'utf8').replace('const label', 'const other = 1;\nconst label'));
  await engine.scan(root, { external: false });
  // surrounding lines differ -> context hash changed -> reopened
  assert.strictEqual(store.open(root).findings[stripe.id].status, 'open', 'FP reopened when context changes');

  // removing code -> full scan resolves; accepted risk stays visible
  const svc = Object.values(store.open(root).findings).find(f => f.title.startsWith('Exported service'));
  await engine.setStatus(root, svc.id, { status: 'accepted_risk', reason: 'legacy', expiry: '2099-01-01' });
  await engine.scan(root, { external: false });
  assert.strictEqual(store.open(root).findings[svc.id].status, 'accepted_risk', 'accepted risk persists');
  fs.writeFileSync(path.join(root, 'firestore.rules'), 'rules_version = "2";\n');
  const s5 = await engine.scan(root, { external: false });
  assert(s5.diff.resolved.length >= 1 && store.open(root).findings[Object.values(store.open(root).findings).find(f => f.ruleId === 'cfg-rules-open').id].status === 'resolved', 'full scan resolves removed issue');

  // dependencies: stubbed OSV -> finding with fixed version; bumping the version resolves it on the next scan
  w('pubspec.lock', 'packages:\n  http:\n    dependency: "direct main"\n    source: hosted\n    version: "0.13.0"\n');
  const realFetch = global.fetch;
  global.fetch = async (url, o) => ({ ok: true, json: async () => String(url).includes('querybatch')
    ? { results: [{ vulns: /0\.13\.0/.test(o.body) ? [{ id: 'GHSA-xxxx' }] : [] }] }
    : { id: 'GHSA-xxxx', aliases: ['CVE-2099-1'], summary: 'test vuln', database_specific: { severity: 'HIGH' }, affected: [{ package: { name: 'http' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '0.13.3' }] }] }] } });
  await engine.scan(root, { external: false });
  const dep = Object.values(store.open(root).findings).find(f => f.ruleId === 'dep-vuln');
  assert(dep && dep.severity === 'high' && dep.dep.fixed === '0.13.3' && dep.dep.cve === 'CVE-2099-1' && dep.dep.affected === '>=0 <0.13.3', 'dependency finding');
  w('pubspec.lock', 'packages:\n  http:\n    dependency: "direct main"\n    source: hosted\n    version: "0.13.3"\n');
  assert((await engine.rescanFinding(root, dep.id)).resolved, 'dep rescan resolves after upgrade');
  global.fetch = async () => { throw new Error('offline'); };
  await engine.scan(root, { external: false });
  assert(store.open(root).findings[dep.id].status === 'resolved' && engine.progress.steps.find(s => s.key === 'deps').status === 'failed', 'offline lookup does not resolve or invent findings');
  global.fetch = realFetch;

  // retention (7 days) + manual delete + clear all
  {
    const d0 = store.open(root), n0 = d0.scans.length;
    assert(n0 >= 3, 'need several scans for retention test');
    d0.scans[0].finishedAt = new Date(Date.now() - 10 * 864e5).toISOString();
    d0.scans[1].finishedAt = new Date(Date.now() - 8 * 864e5).toISOString();
    d0.scans[d0.scans.length - 1].finishedAt = new Date(Date.now() - 30 * 864e5).toISOString();   // newest scan older than 7d is still kept
    const oldRes = Object.values(d0.findings).find(f => f.status === 'resolved'); if (oldRes) oldRes.resolvedAt = new Date(Date.now() - 9 * 864e5).toISOString();
    store.save(root, d0);
    assert(store.maintain(root) >= 2, 'prune removed old scans');
    const d1 = store.open(root);
    assert.strictEqual(d1.scans.length, n0 - 2, 'scans older than 7 days removed');
    assert(d1.scans.length >= 1, 'newest scan always kept');
    if (oldRes) assert(!d1.findings[oldRes.id], 'old resolved findings removed');
    assert.throws(() => store.deleteScan(root, d1.scans[d1.scans.length - 1].id), /latest/, 'cannot delete newest scan');
    if (d1.scans.length > 1) { store.deleteScan(root, d1.scans[0].id); assert.strictEqual(store.open(root).scans.length, d1.scans.length - 1, 'manual delete'); }
    const before = Object.keys(store.open(root).findings).length; assert(before > 0);
    store.clearAll(root);
    assert.strictEqual(store.open(root).scans.length, 0, 'clear all'); assert.strictEqual(Object.keys(store.open(root).findings).length, 0);
    await engine.scan(root, { external: false });   // fresh start works
    assert(store.open(root).scans.length === 1 && store.open(root).findings['SEC-0001'], 'fresh scan after clear restarts IDs');
  }

  // scan data must never be committable: .secscan/ ignores itself
  assert(fs.readFileSync(path.join(root, '.secscan', '.gitignore'), 'utf8').trim() === '*', '.secscan self-ignores');
  {
    const cp = require('child_process'); cp.spawnSync('git', ['init', '-q'], { cwd: root });
    const st = cp.spawnSync('git', ['status', '--porcelain', '--', '.secscan'], { cwd: root, encoding: 'utf8' }).stdout;
    assert.strictEqual(st.trim(), '', 'git sees nothing to commit in .secscan');
    fs.rmSync(path.join(root, '.git'), { recursive: true, force: true });   // later steps expect a non-git folder
  }
  // changed-files mode only touches scanned files (non-git -> must refuse cleanly)
  await assert.rejects(engine.scan(root, { mode: 'changed' }), /git/);
  assert.strictEqual(engine.progress.state, 'failed');

  // server: token required
  const { start } = require('../src/server');
  const srv = await start(root, 0);
  const port = srv.server.address().port;
  assert.strictEqual((await fetch(`http://127.0.0.1:${port}/api/state`)).status, 403, 'api needs token');
  const evil = await new Promise(res => require('http').get({ host: '127.0.0.1', port, path: '/api/state', headers: { 'x-secscan-token': srv.token, host: 'evil.com' } }, r => { r.resume(); res(r.statusCode); }));
  assert.strictEqual(evil, 403, 'host header checked (DNS rebinding)');
  const st = await (await fetch(`http://127.0.0.1:${port}/api/state`, { headers: { 'x-secscan-token': srv.token } })).json();
  assert(st.counts.critical >= 1 && st.score < 70, 'state + critical caps score');
  const page = await (await fetch(`http://127.0.0.1:${port}/`)).text();
  assert(page.includes(srv.token), 'token injected into UI');
  // single file + pasted snippet (scratch project), via the API
  const H = { 'x-secscan-token': srv.token, 'content-type': 'application/json' }, call = async (p, b) => (await fetch(`http://127.0.0.1:${port}/api/${p}`, { method: b ? 'POST' : 'GET', headers: H, body: b && JSON.stringify(b) })).json();
  const wait = async () => { for (let i = 0; i < 100 && (await call('progress')).state === 'scanning'; i++) await new Promise(r => setTimeout(r, 100)); await new Promise(r => setTimeout(r, 200)); };
  const one = path.join(root, 'lib/network/network_manager.dart');
  assert((await call('scan-file', { path: one })).file === 'network_manager.dart'); await wait();
  let fs1 = await call('findings');
  assert(fs1.length >= 1 && fs1.every(f => f.file === 'network_manager.dart') && fs1.some(f => f.ruleId === 'net-dart-bad-cert'), 'single file scan');
  assert((await call('state')).lastOnly[0] === 'network_manager.dart');
  assert((await call('scan-snippet', { code: '<application android:debuggable="true"/>', lang: 'manifest' })).file.endsWith('/AndroidManifest.xml')); await wait();
  fs1 = await call('findings');
  assert(fs1.some(f => f.ruleId === 'and-debuggable' && f.file.includes('paste-')), 'snippet scan applies filename-specific rules');
  assert.match((await call('scan-snippet', { code: 'x', lang: 'nope' })).error, /kind of code/);
  assert.match((await call('scan-file', { path: '/nonexistent/x.kt' })).error, /Not a file/);
  fs.rmSync(path.join(os.homedir(), '.secscan-scratch'), { recursive: true, force: true });
  srv.server.close();

  fs.rmSync(root, { recursive: true, force: true });
  console.log(`selftest passed — ${all.length} findings on first scan, ${s1.total} active`);
})().catch(e => { console.error('SELFTEST FAILED:', e.stack || e); console.error('project left at', root); process.exit(1); });
