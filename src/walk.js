'use strict';
const fs = require('fs'), path = require('path');
const { run } = require('./util');

const EXCLUDE_DIRS = new Set(['build', '.dart_tool', '.gradle', '.idea', '.git', 'node_modules', 'Pods', 'DerivedData', 'coverage', 'generated', 'dist', '.secscan', '.fvm', '.pub-cache', '.next', 'venv', '.venv', '__pycache__', '.cxx', '.vscode', '.svn', '.hg']);
const BINARY = /\.(png|jpe?g|gif|webp|ico|icns|svg|pdf|zip|gz|tgz|jar|aar|apk|aab|ipa|so|a|o|dylib|class|dex|ttf|otf|woff2?|eot|mp[34]|mov|avi|wav|ogg|bin|dat|db|sqlite3?|jks|keystore|p12|pfx|der|lockb|xcuserstate|car|nib|storyboardc|map|wasm)$/i;
const SKIP_TEXT = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Podfile\.lock|Cargo\.lock|go\.sum|pubspec\.lock|gradle\.lockfile)$|\.(g|freezed|gr|mocks)\.dart$|\.min\.(js|css)$/;
const MAX_TEXT = 1.5 * 1024 * 1024;

function walk(root, cfg = {}) {
  const extra = cfg.exclude || [], out = [];
  (function rec(dir) {
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      const abs = path.join(dir, e.name), rel = path.relative(root, abs).split(path.sep).join('/');
      if (e.isSymbolicLink()) continue;
      if (extra.some(x => rel === x || rel.startsWith(x.replace(/\/?$/, '/')))) continue;
      if (e.isDirectory()) { if (!EXCLUDE_DIRS.has(e.name)) rec(abs); continue; }
      if (!e.isFile()) continue;
      let st; try { st = fs.statSync(abs); } catch { continue; }
      out.push({ rel, abs, size: st.size, mtime: st.mtimeMs, binary: BINARY.test(e.name), skipText: SKIP_TEXT.test(rel) });
    }
  })(root);
  return out;
}

// lazy text reader with cache; null for binary/huge/skipped
function reader() {
  const cache = new Map();
  return f => {
    if (cache.has(f.rel)) return cache.get(f.rel);
    let t = null;
    if (!f.binary && !f.skipText && f.size <= MAX_TEXT) {
      try {
        const b = fs.readFileSync(f.abs);
        t = b.subarray(0, 4096).includes(0) ? null : b.toString('utf8');
      } catch { /* unreadable */ }
    }
    cache.set(f.rel, t);
    return t;
  };
}

function detectTech(files) {
  const t = new Set(), any = re => files.some(f => re.test(f.rel));
  if (any(/(^|\/)pubspec\.yaml$/)) { t.add('flutter'); t.add('dart'); } else if (any(/\.dart$/)) t.add('dart');
  if (any(/AndroidManifest\.xml$|(^|\/)build\.gradle(\.kts)?$/)) t.add('android');
  if (any(/\.kt$/)) t.add('kotlin');
  if (any(/\.java$/)) t.add('java');
  if (any(/\.swift$|Info\.plist$|(^|\/)Podfile$/)) t.add('ios');
  if (any(/(^|\/)package\.json$/)) t.add('node');
  if (any(/\.py$|requirements\.txt$/)) t.add('python');
  if (any(/(^|\/)go\.mod$/)) t.add('go');
  if (any(/(^|\/)Dockerfile/)) t.add('docker');
  if (any(/^\.github\/workflows\/|\.gitlab-ci\.yml$/)) t.add('ci');
  if (any(/firebase\.json$|firestore\.rules$|google-services\.json$/)) t.add('firebase');
  return [...t];
}

const git = {
  is: root => run('git', ['rev-parse', '--is-inside-work-tree'], { cwd: root }).ok,
  branch: root => { const r = run('git', ['rev-parse', '--abbrev-ref', 'HEAD'], { cwd: root }); return r.ok ? r.out.trim() : '-'; },
  head: root => { const r = run('git', ['rev-parse', 'HEAD'], { cwd: root }); return r.ok ? r.out.trim() : ''; },
  ignored: (root, rel) => run('git', ['check-ignore', '-q', '--', rel], { cwd: root }).ok,
  tracked: (root, rel) => run('git', ['ls-files', '--error-unmatch', '--', rel], { cwd: root }).ok,
  staged: root => run('git', ['diff', '--cached', '--name-only', '--diff-filter=ACMR'], { cwd: root }).out.split('\n').filter(Boolean),
  // staged + modified + untracked + (optionally) changed vs target branch
  changed(root, base) {
    const s = new Set();
    const add = a => run('git', a, { cwd: root }).out.split('\n').filter(Boolean).forEach(x => s.add(x));
    add(['diff', '--name-only', '--diff-filter=ACMR', 'HEAD']);
    add(['diff', '--cached', '--name-only', '--diff-filter=ACMR']);
    add(['ls-files', '--others', '--exclude-standard']);
    const b = base || ['origin/main', 'origin/master', 'origin/develop', 'main', 'master', 'develop'].find(x => run('git', ['rev-parse', '--verify', '-q', x], { cwd: root }).ok);
    if (b) add(['diff', '--name-only', '--diff-filter=ACMR', `${b}...HEAD`]);
    return [...s];
  },
};

module.exports = { walk, reader, detectTech, git };
