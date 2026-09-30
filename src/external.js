'use strict';
// Adapters: external scanners -> unified finding model. Skipped silently when a tool is not installed.
// NOTE: converters are written against each tool's documented JSON; verify against your installed versions.
const fs = require('fs'), os = require('os'), path = require('path');
const { has, exec, sha, norm } = require('./util');
const { maskLine } = require('./secrets');
const { depFinding } = require('./deps');

const rel = (root, p) => path.isAbsolute(p) ? path.relative(root, p).split(path.sep).join('/') : p.replace(/^\.\//, '');
const SEV = { ERROR: 'high', WARNING: 'medium', INFO: 'low', CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low', UNKNOWN: 'low' };
const codeAt = (root, file, line) => { try { return maskLine(fs.readFileSync(path.join(root, file), 'utf8').split('\n')[line - 1].trim().slice(0, 240), file); } catch { return ''; } };
const guessCat = s => /secret|credential|token|password|api-?key/i.test(s) ? 'secrets' : /crypto|cipher|hash|random/i.test(s) ? 'cryptography' : /sql|inject|command|exec|eval/i.test(s) ? 'injection' : /xss|html/i.test(s) ? 'input-validation' : /tls|ssl|cert|http|network/i.test(s) ? 'network-security' : /auth|jwt|session/i.test(s) ? 'authentication' : 'code-security';

function mk(tool, step, o, root) {
  const code = o.code != null ? o.code : codeAt(root, o.file, o.line);
  return {
    ruleId: `${tool.toLowerCase().replace(/\s+/g, '')}:${o.rule}`, step, detectedBy: [tool], severity: o.sev, category: o.cat, kind: o.kind || 'risk', confidence: o.conf || 'medium',
    cwe: o.cwe || null, owasp: null, masvs: null, title: o.title, file: o.file, line: o.line || 0, code,
    description: o.d || '', risk: o.k || '', impact: [], fix: o.f || '', env: 'unknown', ctxHash: '', fp: sha(`ext|${tool}|${o.rule}|${o.file}|${norm(code)}`),
  };
}

const TOOLS = [
  { name: 'Gitleaks', bin: 'gitleaks', step: 'secrets',
    args: (root, out) => ['detect', '--source', root, '--no-git', '--redact', '--report-format', 'json', '--report-path', out, '--exit-code', '0'], file: true,
    parse: (j, root) => (j || []).map(r => mk('Gitleaks', 'secrets', { rule: r.RuleID, sev: 'high', cat: 'secrets', kind: 'vulnerability', conf: 'high', cwe: 'CWE-798', title: `Possible secret detected: ${r.Description || r.RuleID}`, file: rel(root, r.File), line: r.StartLine, code: maskLine((r.Match || '').slice(0, 200)) }, root)) },
  { name: 'Semgrep', bin: 'semgrep', step: 'code', args: root => ['--config', 'auto', '--json', '--quiet', root],
    parse: (j, root) => ((j && j.results) || []).map(r => {
      const m = (r.extra && r.extra.metadata) || {}, cwe = [].concat(m.cwe || []).join(' ').match(/CWE-\d+/);
      return mk('Semgrep', 'code', { rule: r.check_id, sev: SEV[r.extra.severity] || 'medium', cat: guessCat(r.check_id + ' ' + [].concat(m.category || []).join(' ')), conf: String(m.confidence || 'medium').toLowerCase(), cwe: cwe && cwe[0], title: (r.extra.message || r.check_id).split('\n')[0].slice(0, 140), d: r.extra.message, file: rel(root, r.path), line: r.start && r.start.line }, root);
    }) },
  { name: 'Trivy', bin: 'trivy', step: 'deps', args: root => ['fs', '--format', 'json', '--quiet', '--scanners', 'vuln,secret,misconfig', root],
    parse: (j, root) => {
      const out = [], ECO = { pub: 'Pub', npm: 'npm', gradle: 'Maven', jar: 'Maven', pom: 'Maven', pip: 'PyPI', gomod: 'Go' };
      for (const r of (j && j.Results) || []) {
        const file = rel(root, r.Target);
        for (const v of r.Vulnerabilities || []) {
          const f = depFinding({ eco: ECO[r.Type] || r.Type, name: v.PkgName, version: v.InstalledVersion, file }, v.VulnerabilityID, { summary: v.Title, database_specific: { severity: v.Severity }, affected: [{ ranges: [{ events: [{ fixed: v.FixedVersion }] }] }] });
          f.detectedBy = ['Trivy']; out.push(f);
        }
        for (const s of r.Secrets || []) out.push(mk('Trivy', 'secrets', { rule: s.RuleID, sev: SEV[s.Severity] || 'high', cat: 'secrets', kind: 'vulnerability', conf: 'high', cwe: 'CWE-798', title: `Possible secret detected: ${s.Title}`, file, line: s.StartLine, code: maskLine((s.Match || '').slice(0, 200)) }, root));
        for (const c of r.Misconfigurations || []) out.push(mk('Trivy', 'config', { rule: c.ID, sev: SEV[c.Severity] || 'medium', cat: 'configuration', title: c.Title, d: c.Description, f: c.Resolution, file, line: c.CauseMetadata && c.CauseMetadata.StartLine, code: '' }, root));
      }
      return out;
    } },
  { name: 'OSV Scanner', bin: 'osv-scanner', step: 'deps', args: root => ['--format', 'json', '-r', root],
    parse: (j, root) => {
      const out = [], ECO = { Pub: 'Pub', npm: 'npm', Maven: 'Maven', PyPI: 'PyPI', Go: 'Go' };
      for (const r of (j && j.results) || []) for (const p of r.packages || []) for (const v of p.vulnerabilities || []) {
        const f = depFinding({ eco: ECO[p.package.ecosystem] || p.package.ecosystem, name: p.package.name, version: p.package.version, file: rel(root, r.source.path) }, v.id, v);
        f.detectedBy = ['OSV Scanner']; out.push(f);
      }
      return out;
    } },
];

const available = () => TOOLS.filter(t => has(t.bin)).map(t => t.name);

async function scanExternal(root, warnings, onlyStep) {
  const out = [];
  for (const t of TOOLS) {
    if (!has(t.bin)) continue;
    const tmp = path.join(os.tmpdir(), `secscan-${Date.now()}-${t.bin}.json`);
    const r = await exec(t.bin, t.args(root, tmp), { cwd: root, timeout: 600000 });
    try {
      const raw = t.file ? fs.readFileSync(tmp, 'utf8') : r.out;
      out.push(...t.parse(JSON.parse(raw || 'null'), root));
    } catch (e) { warnings.push(`${t.name}: could not parse output (${e.message})`); }
    try { fs.unlinkSync(tmp); } catch { /* none */ }
  }
  return out;
}

module.exports = { scanExternal, available };
