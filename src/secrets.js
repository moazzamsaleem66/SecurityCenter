'use strict';
// Secret detection + masking. Never store or display a full secret value.

const PATTERNS = [
  { id: 'aws-access-key', title: 'AWS Access Key ID', re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, sev: 'critical' },
  { id: 'github-token', title: 'GitHub Token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b/g, sev: 'critical' },
  { id: 'stripe-live-key', title: 'Stripe Live Secret Key', re: /\b[sr]k_live_[A-Za-z0-9]{16,}\b/g, sev: 'critical' },
  { id: 'slack-token', title: 'Slack Token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, sev: 'high' },
  { id: 'google-api-key', title: 'Google API Key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g, sev: 'low', publicByDesign: true },
  { id: 'private-key', title: 'Private Key Material', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g, sev: 'critical', noValue: true },
  { id: 'hardcoded-jwt', title: 'Hardcoded JWT', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, sev: 'high' },
  { id: 'azure-storage-key', title: 'Azure Storage Account Key', re: /AccountKey=[A-Za-z0-9+/=]{40,}/g, sev: 'critical' },
  { id: 'db-url-credentials', title: 'Database URL with Credentials', re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/'"]+:([^\s@/'"]{3,})@/g, sev: 'critical', group: 1 },
];

const NAMES = 'pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|client[_-]?secret|private[_-]?key|storePassword|keyPassword|auth[_-]?key|jwt[_-]?secret|access[_-]?key|credential';
const GENERIC = new RegExp(`([\\w.-]*(?:${NAMES})[\\w.-]*)["']?\\s*[:=]\\s*["']([^"'\\s$\\{][^"'\\s]{7,})["']`, 'i');
const GRADLE_PW = /\b(storePassword|keyPassword)\s*[:=]?\s*["']([^"'$\s]{4,})["']/;
const KV = new RegExp(`^\\s*([\\w.-]*(?:${NAMES})[\\w.-]*)\\s*[=:]\\s*["']?([^\\s"'#]{6,})["']?\\s*(?:#.*)?$`, 'i');
const XMLSTR = new RegExp(`<string\\s+name="([^"]*(?:secret|token|password|api_?key|private)[^"]*)"[^>]*>([^<]{8,})<`, 'i');
const PUBLIC_XML = /google_api_key|google_app_id|google_crash_reporting_api_key|firebase_database_url|gcm_defaultSenderId|default_web_client_id/i;
const PH = /(your|example|changeme|change_me|xxxx|dummy|sample|placeholder|todo|fixme|replace|insert|enter[_ ]|<.*>|\*{3,}|\.{3}|^null$|^none$|^undefined$|process\.env|getenv|environment|BuildConfig|^\$|^@|^%|^\{\{)/i;

function entropy(s) {
  const f = {};
  for (const c of s) f[c] = (f[c] || 0) + 1;
  return -Object.values(f).reduce((a, n) => a + (n / s.length) * Math.log2(n / s.length), 0);
}
const mask = v => v.length <= 8 ? '*'.repeat(v.length) : v.slice(0, Math.min(6, v.length >> 2)) + '*'.repeat(Math.max(8, v.length - 8)) + v.slice(-2);

function plausible(v) {
  if (PH.test(v) || /\s/.test(v)) return false;
  if (/^[a-z0-9_.-]+$/.test(v) && /[_.-]/.test(v) && !/\d{3}/.test(v)) return false;   // i18n / identifier keys
  if (/^https?:\/\/[^:@]+$/.test(v)) return false;
  if (/^[A-Za-z]+$/.test(v) && v.length < 24) return false;
  return entropy(v) >= 2.5;
}

function kindOf(name) {
  const n = name.toLowerCase();
  if (/storepassword|keypassword/.test(n)) return { kind: 'Keystore/Signing Password', sev: 'high' };
  if (/pass|pwd/.test(n)) return { kind: 'Password', sev: 'high' };
  if (/jwt/.test(n)) return { kind: 'JWT Secret', sev: 'critical' };
  if (/client[_-]?secret/.test(n)) return { kind: 'Client Secret', sev: 'critical' };
  if (/token/.test(n)) return { kind: 'API Token', sev: 'critical' };
  if (/private/.test(n)) return { kind: 'Private Key', sev: 'critical' };
  if (/api[_-]?key|apikey|access[_-]?key/.test(n)) return { kind: 'API Key', sev: 'high' };
  if (/secret/.test(n)) return { kind: 'Secret', sev: 'high' };
  return { kind: 'Credential', sev: 'high' };
}

// -> [{id,title,sev,value,publicByDesign?,conf}]
function findSecrets(line, rel = '') {
  const out = [], seen = new Set();
  const add = o => { if (o.value && !seen.has(o.value)) { seen.add(o.value); out.push(o); } };
  for (const p of PATTERNS) {
    p.re.lastIndex = 0;
    let m;
    while ((m = p.re.exec(line))) add({ id: p.id, title: `Possible ${p.title} Exposed`, sev: p.sev, value: p.noValue ? m[0] : m[p.group || 0], publicByDesign: p.publicByDesign, conf: 'high', noValue: p.noValue });
  }
  const tryNamed = (m, conf) => {
    if (!m || !plausible(m[2])) return;
    const { kind, sev } = kindOf(m[1]);
    add({ id: 'hardcoded-credential', title: `Possible ${kind} Exposed`, sev, value: m[2], conf });
  };
  if (/\.(gradle|kts)$/.test(rel)) tryNamed(line.match(GRADLE_PW), 'high');
  tryNamed(line.match(GENERIC), 'medium');
  if (/\.(properties|env|ini|cfg|ya?ml|toml)$|(^|\/)\.env/.test(rel)) tryNamed(line.match(KV), 'medium');
  if (/\.xml$/.test(rel)) { const m = line.match(XMLSTR); if (m && !PUBLIC_XML.test(m[1])) tryNamed(m, 'medium'); }
  return out;
}

function maskLine(line, rel = '') {
  let s = line;
  for (const f of findSecrets(line, rel)) if (!f.noValue) s = s.split(f.value).join(mask(f.value));
  return s;
}

module.exports = { findSecrets, maskLine, mask, PATTERNS };
