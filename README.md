# Swiftec Security Center — AI Security Review Agent

<img src="ui/assets/logo-128.png" width="64" align="left"> **Service Station Transformation**


Scan → understand → fix → verify → rescan → resolve. Works on **Android/Kotlin/Java, Flutter/Dart, iOS/Swift, Node, Python, Go** projects. Node ≥ 18, **no npm dependencies**.

```bash
node bin/secscan.js serve  /path/to/project     # dashboard at http://localhost:4317 (token-protected, 127.0.0.1 only)
node bin/secscan.js scan   /path/to/project     # CLI scan (--changed --git-history --ai --no-external --fail-on high --json out.json)
node bin/secscan.js staged /path/to/project     # pre-commit secret check;  install-hook wires it up
node bin/secscan.js install-claude /path/to/project   # adds .claude agents + skill + /security-scan to that project
npm test                                        # self-check (builds a vulnerable throwaway project, asserts the lifecycle)
```
Results are stored in `<project>/.secscan/` (add it to that project's `.gitignore`). Nothing is modified in the scanned project except by an approved AI fix (backed up under `.secscan/backups`, undoable).

## Quick start (for anyone who clones this)
1. Install Node.js 18+ (https://nodejs.org). No other dependencies.
2. `git clone <repo-url> && cd <repo>`
3. `node bin/secscan.js serve` — the dashboard opens; choose a project folder and scan.
4. Optional: install the Claude CLI (or set `ANTHROPIC_API_KEY`) to enable Ask AI / Generate Fix / AI review.
Scan history is stored inside each scanned project (`.secscan/`, kept 7 days) — never in this repo.

## What it checks
Secrets (patterns + keyword/entropy, masked everywhere; committed `.env`/keystores/service-account files; optional Git history) · network (TLS bypass, TrustManager, hostname verifier, ATS, network-security-config, HTTP/WS endpoints) · Android (manifest exports, debuggable/backup/cleartext, WebView, PendingIntent, signing, Gradle repos) · Flutter (SharedPreferences/Hive secrets, WebView, local_auth, pubspec sources, debug bypass flags) · logging of tokens/PII · crypto (weak hash **only in security context**, ECB/DES, static keys/IVs, weak random) · injection (SQL/command/eval/XSS) · auth/API (JWT, tokens in URLs, client-only authorization, CORS) · Firebase rules · Docker/GitHub Actions · dependencies (OSV.dev; parsers for pubspec.lock, Gradle/version catalogs/lockfile, package-lock, requirements, go.mod, pom). Debug-only (`kDebugMode`, `BuildConfig.DEBUG`, `src/debug`) is down-ranked; test/example files are skipped except for secrets.

## Workflow rules enforced in code
- A finding becomes **Resolved only after a rescan** confirms it. "Mark as Fixed" triggers the rescan; claiming it fixed does nothing.
- AI fixes: propose → diff shown → explicit approval (`approve:true` + proposal id) → backup → apply → rescan → optional build check. Security result and build result are separate (`Security: resolved · Build: failed`). **Undo AI Fix** restores the backup.
- False Positive / Accepted Risk need a reason; accepted risks (with owner, expiry, ticket) stay in every report; FP is forgotten if the surrounding code changes; expired accepted risks reopen.
- Stable IDs (`SEC-0001`…) survive line moves; scans compare as new / resolved / unchanged / reopened; baseline highlights only new issues.
- A scanner step that fails (e.g. OSV offline) is reported and never treated as "no findings".

## AI
Provider interface in `src/ai.js`: `claude-cli` (default if `claude` is on PATH; read-only tools), `anthropic-api` (`ANTHROPIC_API_KEY`). Force with `SECSCAN_AI=…`, model with `SECSCAN_MODEL`. Used for Ask AI, Generate Fix (minimal/recommended/hardened), and the optional contextual review step. AI-only findings are capped at medium confidence.
External scanners are auto-used if installed (Semgrep, Gitleaks, Trivy, OSV-Scanner) and merged into one finding with "Detected by" listing each source.

## Claude Code
`.claude/` holds the orchestrator + six specialist reviewers, the `security-scan` skill and `/security-scan` command. Reviewers write JSON to `.secscan/agent-findings/`, imported with `secscan import`. Set `SECSCAN_HOME` to this folder (or run `install-claude`, which bakes the path in).

## Config (`<project>/.secscan/config.json`, optional)
`{"exclude":["legacy/"],"build":"flutter analyze"}` — extra excluded paths; custom build/verify command.

## Not verified / known limits
Claude CLI/API calls, external-tool JSON converters, and the live OSV.dev query were not exercised in the build sandbox (network/tools absent): OSV was tested against a stub. Detection is regex + context heuristics, not data-flow analysis — use the AI review step and treat low-confidence findings as prompts to look. PDF export = open the HTML report and print. Not yet built: CI PR gate beyond `--fail-on`, scheduled scans, trend charts beyond the sparkline.

---
© 2026 Moazzam Saleem. All rights reserved.
