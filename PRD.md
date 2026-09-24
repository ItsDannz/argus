# Product Requirements Document (PRD)

## Autonomous Code Security Guard & Patch Agent

|  |  |
| --- | --- |
| **Document Type** | Product Requirements Document |
| **Product Type** | CLI Tool + VS Code Extension |
| **Status** | Draft v1.0 |
| **Owner** | Dann |

---

## 1. Executive Summary

**Autonomous Code Security Guard & Patch Agent** (working name: **CodeGuard**) is a developer-productivity tool that inserts an AI-assisted security and logic review step directly into the local Git workflow. Instead of running as a standalone scanner that developers must remember to invoke, CodeGuard hooks into `git diff` at pre-commit time, analyzes only the changed code, flags security vulnerabilities and logic bugs, and — when connected to an AI API — proposes a one-click patch.

The product is explicitly designed with **two operating modes** so it remains useful and free even without an API key, while unlocking deep, context-aware AI analysis and auto-patching when one is provided.

This PRD defines the problem, users, scope, functional/non-functional requirements, architecture, and mode-switching logic for the MVP, intended as a portfolio-grade DevSecOps + LLM tooling project.

---

## 2. Problem Statement

Most static analysis / security scanning tools fall into one of two unsatisfying categories:

1. **Heavyweight CI/CD scanners** (e.g. SonarQube, Snyk) — powerful, but feedback arrives late (after push/PR), disconnected from the developer's immediate editing context, and usually require paid infrastructure or CI setup.
2. **Simple linters/regex scanners** — fast and local, but shallow. They catch known bad patterns (e.g. `strcpy`) but cannot reason about *logic bugs*, *business-context vulnerabilities*, or *how a diff changes program behavior*.

Developers, especially students and solo/small-team developers, need something in between: a **local, low-friction, pre-commit gate** that gives them AI-level reasoning about *only what they just changed*, without mandatory cloud infrastructure or cost when they don't want it.

---

## 3. Goals & Objectives

| Goal | Success Metric |
| --- | --- |
| Catch security/logic issues before they enter Git history | ≥ 80% detection rate on a seeded test set of known vulnerable patterns (SQLi, hardcoded secrets, unsafe C functions, unhandled exceptions) |
| Keep the tool usable with zero cost/setup | Local Rule-Based Mode works fully offline, no API key required |
| Make AI patching low-friction | From "vulnerability detected" to "patch applied" in ≤ 2 user actions (approve → apply) |
| Demonstrate DevSecOps + LLM tooling competence (portfolio goal) | Working CLI + VS Code extension demo, documented architecture, clear before/after patch examples |
| Avoid blocking developer flow | Diff-only analysis (not full repo scan) keeps scan time low on typical commits |

### Non-Goals (for MVP)

- Not a replacement for full CI/CD security pipelines (e.g. SAST/DAST suites).
- Not a multi-language exhaustive vulnerability database (MVP focuses on a curated, high-value rule set).
- Not a team/collaboration platform — MVP is single-developer, local-first.

---

## 4. Target Users

| Persona | Description | Primary Need |
| --- | --- | --- |
| **Student / Portfolio Developer** (primary) | Building projects, learning secure coding practices | Immediate, educational feedback + something to show in a portfolio |
| **Solo / Indie Developer** | Small projects, no dedicated security team | Cheap, local-first safety net before pushing code |
| **Small Team Lead** | Wants baseline hygiene without enforcing heavy CI tooling on juniors | Lightweight pre-commit gate that's easy to roll out |

---

## 5. Scope

### 5.1 In Scope (MVP)

- Git pre-commit hook integration (via Husky or native `.git/hooks`)
- CLI tool: `codeguard scan`, `codeguard patch`, `codeguard config`
- VS Code extension: inline diagnostics + "Apply Patch" code action on staged changes
- Two operating modes: **Remote AI Mode** and **Local Static Engine Mode**
- Automatic mode fallback when no API key is configured or API call fails
- Risk classification (Critical / High / Medium / Low) per finding
- Patch proposal + diff preview + one-click apply (Remote AI Mode only)
- Config file for excluding paths, choosing model, setting risk threshold to block commit

### 5.2 Out of Scope (MVP)

- Multi-file/whole-repo semantic analysis (only diff-scoped)
- Auto-patch generation in Local Mode (detection only)
- Remote team dashboards / reporting
- Support for AI providers beyond DeepSeek at MVP (architecture should allow adding more later)
- CI/CD (GitHub Actions, etc.) integration — local Git hook only for MVP

---

## 6. Product Modes

### 6.1 Mode 1 — Remote AI Mode (API Key Required)

| Aspect | Detail |
| --- | --- |
| Trigger | Valid API key found in config/env |
| Models | `deepseek-v4.1-flash` for both stages, with reasoning toggled per request: reasoning **off** for fast first-pass triage of the whole diff; reasoning **on** for deep analysis + patch generation on flagged hunks only (cost control: the reasoning call is only invoked on findings, not the whole diff) |
| Capabilities | Contextual logic-bug detection, cross-hunk reasoning, natural-language risk explanation, AI-generated patch diff |
| Output | Two structured shapes (defined in `src/prompts/security-agent-prompts.ts`): triage returns a `ScanFinding` — `{ file, line_range, severity, category, summary }`; deep analysis returns a `PatchSuggestion` — `{ file, line_range, severity, category, explanation, suggested_patch, confidence }`, where `suggested_patch` is empty if the hunk turns out to be a false positive |
| User Action | Review explanation → Accept / Reject / Edit patch → Apply |

### 6.2 Mode 2 — Local Static Engine (Rule-Based, No API Key)

| Aspect | Detail |
| --- | --- |
| Trigger | No API key configured, OR API call fails/times out, OR user explicitly runs `--local` |
| Engine | Regex / pattern-matching rules executed in Node.js against the diff hunks |
| Example Rule Categories | Hardcoded secrets (API key/password-like strings), dangerous C functions (`strcpy`, `gets`, `sprintf`, `system`), raw/concatenated SQL queries, `eval()`/dynamic code execution, weak crypto calls (e.g. `md5`, `DES`) |
| Capabilities | Pattern-based warnings only — no contextual reasoning, no auto-patch |
| Output | `{ file, line, ruleId, severity, message }` |
| User Action | Manual fix (tool only warns; optionally links to a short remediation note per rule) |

### 6.3 Mode Selection Logic

```
1. Read config for API key (env var or config file)
2. If key present:
     → attempt Remote AI Mode
     → if API call fails (timeout, 401, network error): fallback to Local Mode + warn user
3. If key absent:
     → run Local Mode directly (no error, this is expected default state)
4. User can force mode via flag: `codeguard scan --local` / `--remote`
```

---

## 7. Functional Requirements

| ID | Requirement | Priority |
| --- | --- | --- |
| FR-1 | System shall capture the current `git diff` (staged changes) as the analysis unit | Must |
| FR-2 | System shall run automatically via Git pre-commit hook, and support manual invocation (`codeguard scan`) | Must |
| FR-3 | System shall detect operating mode automatically based on API key presence and reachability | Must |
| FR-4 | In Remote Mode, system shall send only the diff (not full files) to the AI API by default, to reduce cost and data exposure | Must |
| FR-5 | In Remote Mode, system shall classify each finding by severity and category | Must |
| FR-6 | In Remote Mode, system shall propose a patch as a diff hunk that can be previewed before applying | Must |
| FR-7 | System shall allow the user to Accept, Reject, or Edit a proposed patch before it's written to disk | Must |
| FR-8 | In Local Mode, system shall run a configurable rule set of regex-based detectors | Must |
| FR-9 | System shall allow blocking the commit if severity exceeds a configured threshold (e.g. block on any "Critical") | Should |
| FR-10 | System shall store the API key securely (not committed to repo; via `.env`/OS keychain) | Must |
| FR-11 | VS Code extension shall surface findings as inline diagnostics with a "quick fix" code action | Should |
| FR-12 | System shall log findings to a local report file for later review (`.codeguard/report.json`) | Could |
| FR-13 | System shall allow custom/user-defined regex rules for Local Mode | Could |

---

## 8. Non-Functional Requirements

| Category | Requirement |
| --- | --- |
| **Performance** | Diff scan (Local Mode) should complete in well under 1s for typical commit sizes; Remote Mode scan should complete within a few seconds per hunk, with visible progress feedback |
| **Security** | API keys never logged or written to any committed file; diffs sent to the API should be redacted/truncated if they contain values matching secret patterns |
| **Reliability** | Any AI API failure must degrade gracefully to Local Mode rather than blocking the commit process entirely |
| **Portability** | CLI must run cross-platform (Windows/macOS/Linux) via Node.js |
| **Extensibility** | AI provider integration should be abstracted behind an interface so other providers (OpenAI, Anthropic, local LLMs) can be added later without rewriting core logic |
| **Usability** | Findings must be human-readable with clear severity, location, and a one-line explanation — not raw JSON dumped to terminal |

---

## 9. Technical Architecture

### 9.1 Tech Stack

| Layer | Technology |
| --- | --- |
| CLI / Extension Runtime | Node.js + TypeScript |
| Git Integration | Git Hook API (via Husky or native hook scripts) + `simple-git` for diff parsing |
| AI Provider | DeepSeek API — `deepseek-v4.1-flash` for both stages (reasoning off for scan, on for patch) |
| Local Rule Engine | Custom regex/pattern-matcher module (no external ML dependency) |
| Config | `.codeguardrc.json` (per-project) + OS-level secure storage or `.env` for API key |
| VS Code Extension | VS Code Extension API (Diagnostics + CodeAction providers) |
| Patch Application | Diff/patch application via a library such as `diff` npm package |
| Testing | Jest + `@swc/jest` (SWC transformer — ts-jest cannot run on TypeScript 7). Type safety is enforced as a separate step via `tsc --noEmit`, run by `npm test` before Jest |

#### 9.1.1 Package layout

The original sketch in this section named only `src/prompts/`, `src/engine/local/`, `src/engine/remote/`, `src/hooks/` and `src/cli.ts`. Building it out showed that config parsing, Git plumbing and report rendering do not belong inside either `cli.ts` or `hooks/pre-commit.ts` — each of those two would have become a file with four unrelated reasons to change. They are separate modules, split by responsibility:

```
codeguard/
├── .codeguardrc.json       this repo's own config — CodeGuard gates its own commits
├── .husky/pre-commit       written by `codeguard install` (Husky detected, not required)
├── src/
│   ├── cli.ts              entry point: scan | install | patch | config
│   ├── exit-codes.ts       0 ok · 1 error · 2 not-implemented · 3 blocked
│   ├── severity.ts         severity ordering and a type guard
│   ├── config/
│   │   ├── schema.ts       .codeguardrc.json shape, defaults, validation, glob matching
│   │   └── load.ts         reads the config; never throws
│   ├── git/repo.ts         staged-diff capture, hook-path discovery
│   ├── hooks/pre-commit.ts the check, the hook body, and the installer
│   ├── prompts/            system prompts + structured-output types (shared with Remote Mode)
│   ├── report/render.ts    human-readable findings, verdict and config warnings
│   └── engine/
│       ├── diff.ts         unified-diff parser — what both engines stand on
│       ├── findings.ts     the finding shape both engines produce
│       ├── threshold.ts    findings → blocking / warned / allowed
│       ├── local/          FR-8: regex rule set over diff hunks (detection only)
│       └── remote/         FR-3..FR-6: two-stage pipeline, provider client, redaction
└── test-fixtures/          deliberately vulnerable mini-repo (Phase 6)
```


### 9.2 High-Level Flow

```
Developer runs `git commit`
        │
        ▼
 Pre-commit Hook triggers CodeGuard CLI
        │
        ▼
 Capture staged diff (git diff --cached)
        │
        ▼
 Mode Detector (API key present & reachable?)
   ├── Yes → Remote AI Mode
   │           ├── v4.1-flash (reasoning off): quick scan of full diff
   │           ├── Flag suspicious hunks
   │           └── v4.1-flash (reasoning on): deep analysis + patch generation (flagged hunks only)
   └── No / Fallback → Local Static Engine
               └── Regex rule set applied to diff hunks
        │
        ▼
 Findings presented to developer (CLI table / VS Code diagnostics)
        │
        ▼
 [Remote Mode only] Developer reviews patch diff → Accept/Reject/Edit
        │
        ▼
 Patch applied to working files (if accepted) → developer re-stages → commit proceeds
```

### 9.3 Data Flow & Privacy Consideration

Only the **diff** (not the full file or repo) is sent to the AI API by default, and a redaction pass strips strings matching secret-like patterns before transmission — this is both a cost-control and privacy safeguard, and should be called out explicitly in the tool's documentation.

---

## 10. User Flows

### 10.1 CLI Flow (Pre-commit)

1. Developer stages changes and runs `git commit -m "..."`.
2. Hook intercepts before commit is finalized.
3. CodeGuard prints a summary table of findings (or "No issues found").
4. If Remote Mode: developer is prompted per finding — `[a]pply patch / [s]kip / [v]iew diff`.
5. If severity threshold is breached and unresolved: commit is blocked with a clear message and override flag (`--no-verify` still works as Git's native escape hatch).

### 10.2 VS Code Extension Flow

1. Developer edits a file; on save (or on stage), extension runs a scan in the background.
2. Findings appear as squiggly underlines + Problems panel entries.
3. Hovering shows severity + explanation.
4. Quick Fix (💡) offers "Apply CodeGuard Patch" when in Remote Mode.

---

## 11. Risks & Assumptions

| Risk | Mitigation |
| --- | --- |
| AI API latency/cost on large diffs | Two-stage model use (flash for triage, reasoner only on flagged hunks); diff-only scope |
| False positives eroding trust | Clear severity tiers, always show explanation, never auto-apply without explicit approval |
| API key leakage | Never write key to repo files; `.gitignore` template shipped by default; redaction before send |
| Local rule set too shallow to feel valuable alone | Curate a focused, high-signal rule set (secrets, unsafe C calls, raw SQL) rather than trying to be comprehensive |
| Users bypass tool via `git commit --no-verify` | Accepted as expected Git behavior — not something to fight; document it as intentional |

---

## 12. Rough Milestones (Portfolio Roadmap)

| Phase | Deliverable |
| --- | --- |
| 1 | CLI skeleton + Git diff capture + Local Rule-Based Engine (secrets, unsafe C, raw SQL) |
| 2 | Config system + pre-commit hook wiring + CLI findings report |
| 3 | Remote AI Mode integration (deepseek-flash scan) |
| 4 | Patch generation (deepseek-reasoner) + accept/reject/apply flow |
| 5 | VS Code extension (diagnostics + quick fix) |
| 6 | Polish: docs, demo repo with seeded vulnerabilities, README with before/after screenshots |

---

## 13. Portfolio Value Statement

This project demonstrates: (1) practical **DevSecOps** thinking — shifting security left into the pre-commit stage; (2) real-world **LLM API integration**, including cost-aware two-model orchestration (fast triage vs. deep reasoning); (3) **developer tooling** craftsmanship across both CLI and IDE surfaces; and (4) thoughtful **fallback/degradation design** (Remote → Local) rather than a single-point-of-failure tool — a pattern valued in production engineering.
