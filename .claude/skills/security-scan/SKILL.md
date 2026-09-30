---
name: security-scan
description: Run the Security Center scan on the current Android/Kotlin/Flutter/iOS/Node project, review findings with specialised reviewer agents, and verify fixes by rescanning. Use when the user asks for a security scan/review/audit, to "scan the project", to fix or rescan a SEC-#### finding, or before a release.
---

# Security scan

Lifecycle: SCAN → UNDERSTAND → FIX → VERIFY → RESCAN → RESOLVE. Deterministic tools find known patterns; you add context (architecture, logic, false-positive triage).

CLI: `node "${SECSCAN_HOME:-.}/bin/secscan.js" <command> [projectPath]` (run from the project root; `SECSCAN_HOME` points at the scanner folder).

| Need | Command |
|---|---|
| Full scan | `scan` (add `--git-history`, `--changed`, `--no-external`) |
| Dashboard | `serve` (prints a localhost URL) |
| Rescan one finding | `rescan SEC-0007` |
| Import agent findings | `import .secscan/agent-findings/<name>.json` |
| Reports | `export --fmt html\|json\|csv --out file` |

Results live in `.secscan/db.json` (masked; safe to read). Finding IDs (SEC-0001…) are stable across scans.

## Agent finding contract
Reviewer agents write `{"findings":[...]}` to `.secscan/agent-findings/<agent-name>.json`; each item:
`{"file":"rel/path","line":N,"title":"…","severity":"critical|high|medium|low|info","category":"authentication|authorization|secrets|cryptography|network-security|api-security|data-storage|logging|input-validation|injection|dependencies|mobile-security|android-security|ios-security|flutter-security|configuration|ci-cd-security|cloud-security|database-security|privacy|code-security|best-practices","confidence":"high|medium|low","kind":"vulnerability|risk|best-practice","cwe":"CWE-nnn|null","description":"…","risk":"…","impact":["…"],"fix":"…"}`

## Rules (non-negotiable)
1. Never print or write a full secret — mask it (`sk_live_****92`).
2. Never edit security-sensitive code silently: show the diff, get the developer's approval, then apply.
3. A finding is Resolved only after `rescan` confirms it. Editing code is not proof.
4. Separate confirmed vulnerabilities from possible risks; AI-only findings are never "high" confidence.
5. Consider Debug vs Staging vs Release (kDebugMode, BuildConfig.DEBUG, build types).
6. Prefer the secure production fix over a temporary bypass; preserve app behaviour.
7. Don't pad the report: skip style nits and unexploitable patterns.

Then follow `/security-scan` (the command) for the orchestration steps.
