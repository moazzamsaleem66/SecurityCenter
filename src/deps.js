'use strict';
// Dependency scanner: parse manifests/lockfiles, query OSV.dev (https://osv.dev) for known vulnerabilities.
const { sha } = require('./util');

const parsers = {
  'pubspec.lock'(t) {
    const out = []; let name = null, ver = null, src = null;
    const flush = () => { if (name && ver && src === 'hosted') out.push({ eco: 'Pub', name, version: ver }); name = ver = src = null; };
    for (const l of t.split('\n')) {
      let m;
      if ((m = l.match(/^  ([\w.-]+):\s*$/))) { flush(); name = m[1]; }
      else if ((m = l.match(/^    source:\s*(\w+)/))) src = m[1];
      else if ((m = l.match(/^    version:\s*"?([^"\s]+)"?/))) ver = m[1];
    }
    flush(); return out;
  },
  'gradle.lockfile'(t) {
    return t.split('\n').map(l => l.match(/^([\w.-]+):([\w.-]+):([\w.+-]+)=/)).filter(Boolean).map(m => ({ eco: 'Maven', name: `${m[1]}:${m[2]}`, version: m[3] }));
  },
  gradle(t) {
    const out = [], re = /["']([\w.-]+):([\w.-]+):([\w.-]+)["']/g; let m;
    while ((m = re.exec(t))) out.push({ eco: 'Maven', name: `${m[1]}:${m[2]}`, version: m[3] });
    return out;
  },
  toml(t) {
    const versions = {}, out = []; let sec = '';
    for (const l of t.split('\n')) {
      const s = l.match(/^\s*\[(.+)\]/); if (s) { sec = s[1]; continue; }
      let m;
      if (sec === 'versions' && (m = l.match(/^\s*([\w.-]+)\s*=\s*"([^"]+)"/))) versions[m[1]] = m[2];
      if (sec === 'libraries') {
        if ((m = l.match(/module\s*=\s*"([^":]+:[^":]+)"[^}]*version(?:\.ref)?\s*=\s*"([^"]+)"/))) out.push({ eco: 'Maven', name: m[1], version: l.includes('version.ref') ? versions[m[2]] : m[2] });
        else if ((m = l.match(/=\s*"([\w.-]+:[\w.-]+):([\w.-]+)"/))) out.push({ eco: 'Maven', name: m[1], version: m[2] });
        else if ((m = l.match(/group\s*=\s*"([^"]+)"[^}]*name\s*=\s*"([^"]+)"[^}]*version(?:\.ref)?\s*=\s*"([^"]+)"/))) out.push({ eco: 'Maven', name: `${m[1]}:${m[2]}`, version: l.includes('version.ref') ? versions[m[3]] : m[3] });
      }
    }
    return out.filter(d => d.version);
  },
  'package-lock.json'(t) {
    let j; try { j = JSON.parse(t); } catch { return []; }
    const out = [];
    for (const [k, v] of Object.entries(j.packages || {})) { const n = k.split('node_modules/').pop(); if (k && n && v.version) out.push({ eco: 'npm', name: n, version: v.version }); }
    return out;
  },
  'requirements.txt'(t) { return t.split('\n').map(l => l.match(/^\s*([A-Za-z0-9_.-]+)==([\w.]+)/)).filter(Boolean).map(m => ({ eco: 'PyPI', name: m[1], version: m[2] })); },
  'go.mod'(t) { return t.split('\n').map(l => l.match(/^\s*(?:require\s+)?([\w.\-/]+\.[\w.\-/]+)\s+v([\w.+-]+)/)).filter(Boolean).map(m => ({ eco: 'Go', name: m[1], version: m[2] })); },
  'pom.xml'(t) {
    const out = [], re = /<dependency>\s*<groupId>([^<$]+)<\/groupId>\s*<artifactId>([^<$]+)<\/artifactId>\s*<version>([^<$]+)<\/version>/g; let m;
    while ((m = re.exec(t))) out.push({ eco: 'Maven', name: `${m[1].trim()}:${m[2].trim()}`, version: m[3].trim() });
    return out;
  },
};
const pick = rel => {
  const b = rel.split('/').pop();
  if (parsers[b]) return b;
  if (/\.(gradle|kts)$/.test(b)) return 'gradle';
  if (b === 'libs.versions.toml' || /\.versions\.toml$/.test(b)) return 'toml';
  return null;
};
const isDepFile = rel => !!pick(rel);

const SEVMAP = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };
const post = (url, body) => fetch(url, { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(20000) }).then(r => r.json());
const get = url => fetch(url, { signal: AbortSignal.timeout(20000) }).then(r => r.json());

async function scanDeps(files, read, warnings) {
  const deps = new Map();
  for (const f of files) {
    const p = pick(f.rel); if (!p) continue;
    const text = read({ ...f, skipText: false }) ?? require('fs').readFileSync(f.abs, 'utf8');
    for (const d of parsers[p](text)) {
      if (!d.version || /[$+{]/.test(d.version)) continue;
      const k = `${d.eco}|${d.name}|${d.version}`;
      if (!deps.has(k)) deps.set(k, { ...d, file: f.rel });
    }
  }
  const list = [...deps.values()];
  if (!list.length) return [];
  const findings = [];
  try {
    const ids = new Set(), hit = new Map();
    for (let i = 0; i < list.length; i += 500) {
      const chunk = list.slice(i, i + 500);
      const r = await post('https://api.osv.dev/v1/querybatch', { queries: chunk.map(d => ({ package: { name: d.name, ecosystem: d.eco }, version: d.version })) });
      (r.results || []).forEach((res, j) => { for (const v of res.vulns || []) { ids.add(v.id); (hit.get(chunk[j]) || hit.set(chunk[j], []).get(chunk[j])).push(v.id); } });
    }
    const info = {}, arr = [...ids].slice(0, 300);
    for (let i = 0; i < arr.length; i += 8) await Promise.all(arr.slice(i, i + 8).map(async id => { try { info[id] = await get(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`); } catch { info[id] = { id }; } }));
    for (const [d, vids] of hit) for (const id of vids) findings.push(depFinding(d, id, info[id] || { id }));
    if (ids.size > 300) warnings.push(`Dependency details truncated to 300 of ${ids.size} advisories.`);
  } catch (e) {
    // throw so the scan does not treat "no data" as "no vulnerabilities" (would falsely resolve findings)
    throw new Error(`OSV.dev lookup failed (${e.message}); ${list.length} dependencies parsed but not checked`);
  }
  return findings;
}

function depFinding(d, id, v) {
  const aff = (v.affected || []).find(a => a.package && a.package.name === d.name) || (v.affected || [])[0] || {};
  let fixed = '', range = '';
  for (const r of aff.ranges || []) { for (const e of r.events || []) if (e.fixed && !fixed) fixed = e.fixed; range = (r.events || []).map(e => e.introduced !== undefined ? `>=${e.introduced}` : e.fixed ? `<${e.fixed}` : '').filter(Boolean).join(' '); if (fixed) break; }
  const cve = (v.aliases || []).find(a => a.startsWith('CVE-')) || (id.startsWith('CVE-') ? id : '');
  const sev = SEVMAP[(v.database_specific && v.database_specific.severity || '').toUpperCase()] || 'medium';
  const cwe = v.database_specific && v.database_specific.cwe_ids && v.database_specific.cwe_ids[0] || null;
  return {
    ruleId: 'dep-vuln', step: 'deps', detectedBy: ['Dependency Scanner'], severity: sev, category: 'dependencies', kind: 'vulnerability', confidence: 'high',
    cwe, owasp: 'M2: Inadequate Supply Chain Security', masvs: null, title: `Vulnerable dependency: ${d.name} ${d.version} (${cve || id})`,
    file: d.file, line: 0, code: `${d.name}@${d.version}`, description: v.summary || `Known vulnerability ${id} affects ${d.name} ${d.version}.`,
    risk: 'Known vulnerabilities in dependencies can be exploited without touching your own code.', impact: ['Depends on the advisory — see reference'],
    fix: fixed ? `Upgrade ${d.name} to ${fixed} or later.` : 'No fixed version listed; look for an alternative or mitigation.', env: 'unknown', ctxHash: '',
    dep: { name: d.name, ecosystem: d.eco, current: d.version, affected: range || '-', severity: sev, cve: cve || id, osv: id, fixed: fixed || '-' },
    fp: sha(`dep-vuln|${d.eco}|${d.name}|${d.version}|${id}`),
  };
}

module.exports = { scanDeps, isDepFile, depFinding };
