---
description: Scan the project for security issues, review with specialist agents, and report
argument-hint: "[--changed] [--git-history] [finding-id to rescan]"
---

Use the **security-orchestrator** agent to run a security scan of this project. Arguments: $ARGUMENTS

If the argument is a finding ID (SEC-####), only run `node "${SECSCAN_HOME:-.}/bin/secscan.js" rescan <id>` and report whether it is resolved.
Otherwise: deterministic scan first, then specialist reviewers in parallel, import their findings, and give me a prioritised summary (Critical/High first) with the top fixes. Do not modify code — offer fixes as diffs for my approval.
