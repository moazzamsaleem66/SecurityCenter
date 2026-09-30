'use strict';
// Pluggable AI provider + prompt builders. A provider is { name, available(), ask(prompt, {cwd}) -> Promise<string> }.
// Add another model by adding an entry to PROVIDERS and selecting it with SECSCAN_AI=<name>.
const fs = require('fs'), path = require('path');
const { has, exec, sha, norm } = require('./util');
const { maskLine } = require('./secrets');

const CATS = ['authentication', 'authorization', 'secrets', 'cryptography', 'network-security', 'api-security', 'data-storage', 'logging', 'input-validation', 'injection', 'dependencies', 'mobile-security', 'android-security', 'ios-security', 'flutter-security', 'configuration', 'ci-cd-security', 'cloud-security', 'database-security', 'privacy', 'code-security', 'best-practices'];

const PROVIDERS = {
  'claude-cli': {
    available: () => has('claude'),
    // read-only tools: the model can look around the project but cannot edit anything
    ask: async (prompt, { cwd }) => {
      const args = ['-p', '--output-format', 'text', '--allowedTools', 'Read,Grep,Glob'];
      if (process.env.SECSCAN_MODEL) args.push('--model', process.env.SECSCAN_MODEL);
      const r = await exec('claude', args, { cwd, input: prompt, timeout: 300000 });
      if (!r.ok && !r.out) throw new Error(`claude CLI failed: ${(r.err || '').slice(0, 300)}`);
      return r.out.trim();
    },
  },
  'anthropic-api': {
    available: () => !!process.env.ANTHROPIC_API_KEY,
    ask: async prompt => {
      const r = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST', signal: AbortSignal.timeout(300000),
        headers: { 'content-type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({ model: process.env.SECSCAN_MODEL || 'claude-sonnet-5-5', max_tokens: 8000, messages: [{ role: 'user', content: prompt }] }),
      });
      const j = await r.json();
      if (!r.ok) throw new Error(j.error && j.error.message || `API ${r.status}`);
      return (j.content || []).map(c => c.text || '').join('').trim();
    },
  },
};

function provider() {
  const want = process.env.SECSCAN_AI;
  if (want === 'none') return null;
  const name = want || Object.keys(PROVIDERS).find(n => PROVIDERS[n].available());
  return name && PROVIDERS[name] && PROVIDERS[name].available() ? { name, ...PROVIDERS[name] } : null;
}

const snippet = (root, file, line, r = 25) => {
  try {
    const L = fs.readFileSync(path.join(root, file), 'utf8').split('\n'), a = Math.max(0, line - 1 - r), b = Math.min(L.length, line + r);
    return L.slice(a, b).map((l, i) => `${String(a + i + 1).padStart(5)}  ${l}`).join('\n');
  } catch { return ''; }
};
const brief = f => JSON.stringify({ id: f.id, title: f.title, severity: f.severity, category: f.category, file: f.file, line: f.line, cwe: f.cwe, confidence: f.confidence, env: f.env, detectedCode: f.code, description: f.description, risk: f.risk, detectedBy: f.detectedBy });
const RULES = 'Rules: never reproduce full secret values (mask them); be concise and developer-focused; consider Debug vs Release behaviour; preserve application functionality.';

const askPrompt = (root, f, q, tech) => `You are a security engineer reviewing a finding from a code scanner in project at cwd (technologies: ${tech.join(', ') || 'unknown'}).
${RULES}

FINDING: ${brief(f)}

CODE CONTEXT (secrets may be present in the file — do not repeat them):
${maskLine(snippet(root, f.file, f.line))}

${(f.chat || []).slice(-6).map(m => `${m.role.toUpperCase()}: ${m.text}`).join('\n')}
DEVELOPER QUESTION: ${q}

If the question is a general "explain" request, answer under these headings: What is wrong / Why it is a risk / How it could be exploited / What should be changed / Will changing it affect other functionality / Recommended secure implementation. You may use Read/Grep/Glob to inspect related files. Do not modify anything.`;

const MODES = {
  minimal: 'Produce the smallest change that removes the vulnerability.',
  recommended: 'Produce the recommended, idiomatic secure fix.',
  hardened: 'Produce a production-hardened fix (defence in depth, secure defaults), still keeping the diff as small as reasonable.',
};
const fixPrompt = (root, f, mode, tech) => `You are a security engineer. Propose a code fix for this finding (technologies: ${tech.join(', ') || 'unknown'}).
${RULES}
${MODES[mode] || MODES.recommended}

FINDING: ${brief(f)}

FILE CONTEXT:
${snippet(root, f.file, f.line, 40)}

Respond with ONLY one JSON object, no prose, no code fences:
{"summary":"one sentence","edits":[{"file":"path relative to project root","old":"EXACT existing text to replace (must occur exactly once in the file; include enough lines to be unique)","new":"replacement text"}],"sideEffects":"what else might change or need updating","manualSteps":"steps you cannot automate (e.g. rotate a credential), or empty"}
Do not include line-number prefixes in "old". If the fix requires no code change, return an empty edits array and explain in manualSteps.`;

const reviewPrompt = (file, text) => `You are a security reviewer doing a contextual review of one file. Deterministic scanners already cover regex-detectable issues; focus on logic/context issues: authentication & session handling, authorization enforced only on the client, insecure token handling, improper validation, unsafe storage, business-logic abuse, debug-only bypasses that could reach release builds.
${RULES}
Only report issues you can point to a specific line for. Prefer few, high-signal findings; do not report style issues.

FILE: ${file}
${text.split('\n').map((l, i) => `${String(i + 1).padStart(5)}  ${l}`).join('\n')}

Respond with ONLY a JSON array (empty array if nothing): [{"line":N,"title":"...","severity":"critical|high|medium|low|info","category":"one of ${CATS.join('|')}","confidence":"high|medium|low","kind":"vulnerability|risk|best-practice","cwe":"CWE-nnn or null","description":"...","risk":"...","impact":["..."],"fix":"..."}]`;

function parseJson(text, open = '{') {
  const s = text.replace(/```(?:json)?/g, '');
  const close = open === '{' ? '}' : ']', a = s.indexOf(open), b = s.lastIndexOf(close);
  if (a < 0 || b < a) throw new Error('AI response did not contain JSON');
  return JSON.parse(s.slice(a, b + 1));
}

// normalise raw AI/agent findings [{file,line,title,...}] -> finding objects
function toFindings(list, root, source = 'Claude AI') {
  const out = [];
  for (const r of list || []) {
    if (!r || !r.file || !r.title) continue;
    const file = r.file.replace(/^\.\//, '');
    let lines = []; try { lines = fs.readFileSync(path.join(root, file), 'utf8').split('\n'); } catch { continue; }
    let line = Math.min(Math.max(+r.line || 1, 1), lines.length);
    const code = maskLine((lines[line - 1] || '').trim().slice(0, 240), file);
    const sev = ['critical', 'high', 'medium', 'low', 'info'].includes(r.severity) ? r.severity : 'medium';
    const cat = CATS.includes(r.category) ? r.category : 'code-security';
    out.push({
      ruleId: 'ai-review', step: 'ai', detectedBy: [source], severity: sev, category: cat, kind: ['vulnerability', 'risk', 'best-practice', 'quality', 'info'].includes(r.kind) ? r.kind : 'risk',
      confidence: r.confidence === 'low' ? 'low' : 'medium',   // AI-only findings never claim "high"
      cwe: /^CWE-\d+$/.test(r.cwe || '') ? r.cwe : null, owasp: null, masvs: null, title: String(r.title).slice(0, 160), file, line, code,
      description: r.description || '', risk: r.risk || '', impact: [].concat(r.impact || []), fix: r.fix || '', env: 'unknown', ctxHash: '',
      fp: sha(`ai|${cat}|${file}|${norm(code)}`),
    });
  }
  return out;
}

const AI_HINT = /auth|login|session|token|interceptor|network|api|client|http|secure|crypto|payment|biometric|permission|repository|service|manager|firebase|webview|intent|deeplink/i;
async function reviewFiles(root, files, read, p, warnings, limit = 8) {
  const cand = files.filter(f => /\.(dart|kt|java|swift|js|ts|py)$/.test(f.rel) && f.size < 60000 && !/test|mock|generated/i.test(f.rel))
    .map(f => ({ f, s: (f.rel.match(new RegExp(AI_HINT.source, 'gi')) || []).length })).filter(x => x.s).sort((a, b) => b.s - a.s).slice(0, limit);
  const out = [];
  for (const { f } of cand) {
    try {
      const raw = parseJson(await p.ask(reviewPrompt(f.rel, maskLine(read(f) || '')), { cwd: root }), '[');
      out.push(...toFindings(raw.map(x => ({ ...x, file: f.rel })), root, 'Claude AI'));
    } catch (e) { warnings.push(`AI review of ${f.rel} failed: ${e.message}`); }
  }
  return out;
}

module.exports = { provider, askPrompt, fixPrompt, parseJson, toFindings, reviewFiles, CATS };
