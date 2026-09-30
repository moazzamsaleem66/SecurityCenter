'use strict';
const fs = require('fs'), path = require('path');
const { RULES, lineOf } = require('./rules');
const { findSecrets, maskLine } = require('./secrets');
const { SEV, sha, norm, down } = require('./util');
const { git } = require('./walk');

const TESTPATH = /(^|\/)(test|tests|androidTest|integration_test|__tests__|__mocks__|mocks?|fixtures?|examples?|samples?)\//i;
const TESTFILE = /(_test\.dart|Tests?\.(kt|java|swift)|\.(spec|test)\.[jt]sx?|_test\.go|(^|\/)test_[^/]*\.py)$/;
const DBGCTX = /kDebugMode|!\s*kReleaseMode|BuildConfig\.DEBUG|\bif\s*\(\s*DEBUG\b|\bassert\s*\(|#if DEBUG|__DEV__|NODE_ENV\s*[!=]==?\s*['"]development/;
const COMMENT = /^\s*(\/\/|\/\*|\*|#|<!--)/;
const SENSITIVE_FILE = /(^|\/)(\.env(\.(?!example|sample|template)[\w.-]+)?|key\.properties|[^/]*\.(jks|keystore|p12|pfx|pem)|[^/]*service[-_]?account[^/]*\.json|[^/]*firebase-adminsdk[^/]*\.json|id_rsa|id_ed25519|\.npmrc|\.pypirc|\.htpasswd)$/i;

const envOf = (rel, lines, i) =>
  TESTPATH.test(rel) || TESTFILE.test(rel) ? 'test'
    : /(^|\/)src\/debug\//.test(rel) ? 'debug'
      : lines.slice(Math.max(0, i - 4), i + 1).some(l => DBGCTX.test(l)) ? 'debug' : 'unknown';

function mkFinding(base, o) {
  let severity = o.sev || base.sev, conf = o.conf || base.conf || 'medium', env = o.env || base.env || 'unknown';
  if (env === 'debug' || env === 'test') severity = down(severity);
  if (conf === 'low' && SEV.indexOf(severity) > SEV.indexOf('medium')) severity = 'medium';
  return {
    ruleId: base.id, step: base.sc, detectedBy: ['Static Rule'],
    severity, category: base.cat, kind: o.kind || base.kind || 'risk', confidence: conf,
    cwe: o.cwe || base.cwe || null, owasp: base.owasp || null, masvs: base.masvs || null,
    title: o.title || base.title, file: o.file, line: o.line || 0,
    code: o.code == null ? '' : o.code, description: o.d || base.d || '', risk: o.k || base.k || '',
    impact: base.i || [], fix: o.f || base.f || '', env, ctxHash: o.ctxHash || '',
    fp: sha(`${base.id}|${o.file}|${o.fpText || ''}`),
  };
}

// run the rule table for one scanner step over a set of files
function runRules(step, files, read, extra = {}) {
  const out = [], rules = RULES.filter(r => r.sc === step);
  for (const f of files) {
    const text = read(f);
    if (text == null) continue;
    const rs = rules.filter(r => !r.files || r.files.test(f.rel));
    if (!rs.length) continue;
    const lines = text.split('\n'), counts = {};
    for (const r of rs) {
      const hits = [];
      if (r.check) for (const h of r.check(text, f.rel, lines)) hits.push(h);
      if (r.ml) { const re = new RegExp(r.ml.source, 'g' + (r.ml.flags.replace('g', ''))); let m; while ((m = re.exec(text))) hits.push({ line: lineOf(text, m.index), m, idx: m.index }); }
      if (r.re) {
        for (let i = 0; i < lines.length; i++) {
          const ln = lines[i];
          if (ln.length > 2000 || COMMENT.test(ln)) continue;
          const m = ln.match(r.re);
          if (m) hits.push({ line: i + 1, m });
        }
      }
      for (const h of hits) {
        const i = h.line - 1, raw = lines[i] || '';
        const env = envOf(f.rel, lines, i);
        if (env === 'test' && !r.tests) continue;
        const N = r.near || 0;
        const near = lines.slice(Math.max(0, i - N), i + N + 1).join('\n');
        let ov = {};
        if (r.refine) {
          const res = r.refine({ m: h.m, line: raw, near, text, idx: h.idx, rel: f.rel, lines, i });
          if (res === false) continue;
          ov = res && typeof res === 'object' ? res : {};
        }
        if (r.oncePerFile) { const k = `${r.id}|${f.rel}`; if (counts[k]) continue; counts[k] = 1; }
        const code = h.code != null ? h.code : maskLine(raw.trim().slice(0, 240), f.rel);
        const ctxHash = sha(lines.slice(Math.max(0, i - 2), i + 3).map(norm).join('|'));
        const base = { ...r };
        const fnd = mkFinding(base, { ...h, ...ov, env: ov.env || env, file: f.rel, code, ctxHash, fpText: norm(code) });
        fnd.fp = sha(`${r.id}|${f.rel}|${norm(code)}|${h.title || ov.title || ''}`);
        out.push(fnd);
      }
    }
  }
  return dedupeFp(out);
}

// identical fingerprints within one scan get an occurrence suffix so IDs stay distinct but stable
function dedupeFp(list) {
  const seen = {};
  for (const f of list) { const n = seen[f.fp] = (seen[f.fp] || 0) + 1; if (n > 1) f.fp = `${f.fp}#${n}`; }
  return list;
}

const SECRET_META = {
  title: null, cat: 'secrets', kind: 'vulnerability', cwe: 'CWE-798', owasp: 'M1: Improper Credential Usage', masvs: 'MASVS-STORAGE-1',
  d: 'A value that looks like a credential is stored in source or configuration. The value is masked here.',
  k: 'Anyone with repository, build or app-binary access can extract and use the credential.',
  i: ['Unauthorized access to backend/third-party services', 'Account or infrastructure compromise'],
  f: 'Revoke/rotate the credential, remove it from the repository (and Git history), and load it from a secret manager, CI secret or untracked environment file.',
};

function secretsStep(files, read, root, inGit) {
  const out = [];
  for (const f of files) {
    const text = read(f);
    if (text != null) {
      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const ln = lines[i];
        if (ln.length > 4000) continue;
        for (const s of findSecrets(ln, f.rel)) {
          const env = envOf(f.rel, lines, i);
          let sev = s.sev, title = s.title, kind = 'vulnerability';
          if (s.publicByDesign && /google-services\.json$|GoogleService-Info\.plist$/.test(f.rel)) continue;   // covered by cfg-firebase-client-config
          if (s.publicByDesign) { kind = 'best-practice'; if (/google-services|GoogleService-Info|firebase_options/.test(f.rel)) sev = 'info'; title = 'Google API key in source (public by design; verify it is restricted)'; }
          const code = maskLine(ln.trim().slice(0, 240), f.rel);
          const fnd = mkFinding({ ...SECRET_META, id: `secret-${s.id}`, sc: 'secrets', cat: 'secrets', sev, conf: s.conf }, { kind, title, file: f.rel, line: i + 1, code, env, fpText: norm(code), ctxHash: sha(lines.slice(Math.max(0, i - 2), i + 3).map(norm).join('|')) });
          fnd.valueHash = sha(s.value, 12);
          out.push(fnd);
        }
      }
    }
    // secret-bearing files that should not be in a repository
    if (SENSITIVE_FILE.test(f.rel)) {
      let risky = true, tracked = false;
      if (inGit) { tracked = git.tracked(root, f.rel); risky = tracked || !git.ignored(root, f.rel); }
      if (risky) {
        const priv = /\.(jks|keystore|p12|pfx|pem)$|id_rsa|id_ed25519|service|adminsdk/i.test(f.rel);
        out.push(mkFinding({ id: 'secret-file', sc: 'secrets', cat: 'secrets', sev: tracked || priv ? 'high' : 'medium', kind: 'vulnerability', conf: 'high', cwe: 'CWE-540', owasp: 'M1: Improper Credential Usage',
          d: tracked ? 'This secret-bearing file is tracked by Git.' : inGit ? 'This secret-bearing file is not git-ignored and could be committed.' : 'Secret-bearing file present (not a git repository, so ignore status is unknown).',
          k: 'Keys/credentials in version control are exposed to everyone with repo access, including history.', i: ['Credential exposure', 'Release signing key compromise'],
          f: 'Add to .gitignore, remove from tracking (git rm --cached), rotate the credential, and store it outside the repository.' },
          { title: `Sensitive file in repository: ${path.basename(f.rel)}`, file: f.rel, line: 0, code: '', fpText: 'file' }));
      }
    }
  }
  return dedupeFp(out);
}

// scan everything for a file set (used by rescan-finding); `steps` limits which scanners run
function scanFiles(steps, files, read, root, inGit) {
  const out = [];
  for (const s of steps) {
    if (s === 'secrets') out.push(...secretsStep(files, read, root, inGit));
    else if (['code', 'network', 'android', 'ios', 'flutter', 'config'].includes(s)) out.push(...runRules(s, files, read));
  }
  return out;
}

module.exports = { runRules, secretsStep, scanFiles, envOf, SENSITIVE_FILE };
