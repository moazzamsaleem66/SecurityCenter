#!/usr/bin/env node
'use strict';
const fs = require('fs'), path = require('path');
const engine = require('../src/engine'), store = require('../src/store'), report = require('../src/report');
const { git } = require('../src/walk');
const { SEV } = require('../src/util');

const argv = process.argv.slice(2), cmd = argv[0] || 'help';
const flag = n => argv.includes(`--${n}`);
const opt = (n, d) => { const i = argv.indexOf(`--${n}`); return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : d; };
const VAL = new Set(['port', 'fail-on', 'json', 'fmt', 'out', 'source', 'base']);
const pos = [];
for (let i = 1; i < argv.length; i++) { const a = argv[i]; if (a.startsWith('--')) { if (VAL.has(a.slice(2))) i++; } else pos.push(a); }
const root = path.resolve(pos[0] || '.');

const HELP = `Security Center — Service Station Transformation

  secscan serve   [path] [--port 4317]     open the Security Center dashboard
  secscan scan    [path] [--changed] [--git-history] [--ai] [--no-external]
                         [--fail-on critical|high|medium] [--json out.json]
  secscan staged  [path]                   pre-commit: scan staged files for secrets/high findings
  secscan rescan  <SEC-0001> [path]        rescan one finding
  secscan import  <file.json> [path]       import findings written by Claude Code agents
  secscan export  [path] --fmt json|csv|html --out file
  secscan baseline [path]                  treat current open findings as the baseline
  secscan install-hook [path]              install git pre-commit secret check
  secscan install-claude [path]            copy .claude agents/skill/command into a project
`;

function table(scan) {
  const c = scan.counts;
  console.log(`\n${scan.id}  (${scan.mode})  branch ${scan.branch}  score ${scan.score}/100`);
  console.log(SEV.slice().reverse().map(k => `${k}: ${c[k]}`).join('   '));
  const d = scan.diff;
  console.log(`new ${d.new.length} · resolved ${d.resolved.length} · unchanged ${d.unchanged.length} · reopened ${d.reopened.length}`);
  scan.warnings.forEach(w => console.log('! ' + w));
}

(async () => {
  try {
    if (cmd === 'serve') {
      const { start } = require('../src/server');
      const { lastProject } = require('../src/server');
      const r = await start(pos[0] ? root : lastProject() || root, +opt('port', 4317));
      console.log(`Security Center → ${r.url}\nPick the project folder in the page (Choose Folder). Add .secscan/ to that project's .gitignore.`);
      if (!flag('no-open')) { try { require('child_process').spawn(process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'cmd' : 'xdg-open', process.platform === 'win32' ? ['/c', 'start', r.url] : [r.url], { detached: true, stdio: 'ignore' }).on('error', () => {}).unref(); } catch { /* ignore */ } }
    } else if (cmd === 'scan') {
      const s = await engine.scan(root, { mode: flag('changed') ? 'changed' : 'full', gitHistory: flag('git-history'), ai: flag('ai'), external: !flag('no-external') });
      table(s);
      if (opt('json')) fs.writeFileSync(opt('json'), report.json(root));
      const fo = opt('fail-on');
      if (fo && SEV.slice(SEV.indexOf(fo)).some(k => s.counts[k] > 0)) { console.error(`Failing: findings at or above "${fo}".`); process.exit(1); }
    } else if (cmd === 'staged') {
      const files = git.staged(root);
      if (!files.length) return;
      const { walk, reader } = require('../src/walk'), scanners = require('../src/scanners');
      const set = new Set(files), fl = walk(root).filter(f => set.has(f.rel)), read = reader();
      const hits = scanners.scanFiles(['secrets', 'code'], fl, read, root, true).filter(f => ['critical', 'high'].includes(f.severity) && f.category === 'secrets');
      hits.forEach(f => console.error(`[${f.severity}] ${f.title}  ${f.file}:${f.line}\n    ${f.code}`));
      if (hits.length) { console.error('\nCommit blocked: possible secret in staged files. (Bypass only if false positive: git commit --no-verify)'); process.exit(1); }
    } else if (cmd === 'rescan') {
      const r = await engine.rescanFinding(path.resolve(pos[1] || '.'), pos[0]);
      console.log(r.message);
    } else if (cmd === 'import') {
      const r = engine.importFindings(path.resolve(pos[1] || '.'), [].concat(JSON.parse(fs.readFileSync(pos[0], 'utf8')).findings || JSON.parse(fs.readFileSync(pos[0], 'utf8'))), opt('source', 'Claude AI'));
      console.log(`Imported ${r.imported} new finding(s); ${r.merged} corroborated existing findings.`); table(r.scan);
    } else if (cmd === 'export') {
      const fmt = opt('fmt', 'json'), out = opt('out', `security-report.${fmt}`);
      fs.writeFileSync(out, report[fmt](root)); console.log('Wrote ' + out);
    } else if (cmd === 'baseline') {
      console.log(`Baseline set: ${engine.baseline(root)} finding(s).`);
    } else if (cmd === 'install-hook') {
      const hook = path.join(root, '.git', 'hooks', 'pre-commit');
      if (!fs.existsSync(path.dirname(hook))) throw new Error('not a git repository');
      if (fs.existsSync(hook)) throw new Error(`${hook} already exists — add this line manually:\n  node "${__filename}" staged "$(git rev-parse --show-toplevel)"`);
      fs.writeFileSync(hook, `#!/bin/sh\nnode "${__filename}" staged "$(git rev-parse --show-toplevel)"\n`, { mode: 0o755 });
      console.log('Installed ' + hook);
    } else if (cmd === 'install-claude') {
      const home = path.join(__dirname, '..'), src = path.join(home, '.claude'), dst = path.join(root, '.claude');
      fs.cpSync(src, dst, { recursive: true });
      const fix = d => fs.readdirSync(d, { withFileTypes: true }).forEach(e => { const p = path.join(d, e.name); if (e.isDirectory()) return fix(p); if (p.endsWith('.md')) fs.writeFileSync(p, fs.readFileSync(p, 'utf8').split('${SECSCAN_HOME:-.}').join('${SECSCAN_HOME:-' + home + '}')); });
      fix(dst);
      console.log(`Installed agents, skill and /security-scan command into ${dst}`);
    } else console.log(HELP);
  } catch (e) { console.error('Error: ' + e.message); process.exit(2); }
})();
