'use strict';
const crypto = require('crypto'), cp = require('child_process');

const SEV = ['info', 'low', 'medium', 'high', 'critical'];
const sha = (s, n = 16) => crypto.createHash('sha1').update(String(s)).digest('hex').slice(0, n);
const norm = s => String(s).replace(/\s+/g, ' ').trim();
const down = s => SEV[Math.max(0, SEV.indexOf(s) - 1)];
const now = () => new Date().toISOString();

const run = (cmd, args = [], o = {}) => {
  const r = cp.spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 256 << 20, ...o });
  return { ok: r.status === 0, out: r.stdout || '', err: r.stderr || '', status: r.status };
};
const has = c => run(process.platform === 'win32' ? 'where' : 'which', [c]).ok;

// async exec with timeout; never throws
const exec = (cmd, args, { cwd, input, timeout = 300000, shell = false } = {}) => new Promise(res => {
  let out = '', err = '', p;
  try { p = cp.spawn(cmd, args, { cwd, shell }); } catch (e) { return res({ ok: false, out, err: String(e) }); }
  const t = setTimeout(() => p.kill('SIGKILL'), timeout);
  p.stdout.on('data', d => out += d);
  p.stderr.on('data', d => err += d);
  p.on('error', e => { clearTimeout(t); res({ ok: false, out, err: String(e) }); });
  p.on('close', c => { clearTimeout(t); res({ ok: c === 0, out, err, status: c }); });
  p.stdin.on('error', () => {});
  p.stdin.end(input == null ? undefined : input);
});

module.exports = { SEV, sha, norm, down, now, run, has, exec };
