# CodeGuard — Agent Build Brief (for Claude Code)

## How to Use This Document

Paste this entire document as your first message to Claude Code in a fresh, empty repo. Before starting, also add these two files to the repo so the agent can read them:

- `PRD.md` — the full product requirements document
- `src/prompts/security-agent-prompts.ts` — the system prompts and types for the AI scan/patch stages (already written — use as-is, do not rewrite)

---

## Role & Goal

You are implementing **CodeGuard**, an Autonomous Code Security Guard & Patch Agent, exactly as specified in `PRD.md`. Read `PRD.md` in full before writing any code. Treat it as the source of truth for scope, requirements (FR-1 through FR-13), and architecture (§9).

## Ground Rules (apply to every phase, no exceptions)

1. **Explain as you build.** Walk through the code you write line-by-line in chat, not just as code comments — assume I want to actually understand each piece, not just receive a finished file.
2. **Build incrementally.** Complete one phase fully, then STOP and report before starting the next phase (see "End of Phase Report" below). Do not attempt to build the entire project in one pass, even if you think you can.
3. **Don't silently deviate from the PRD.** If something in the PRD is ambiguous or you think a different approach is better (e.g. see the model note below), say so explicitly and ask, rather than deciding unilaterally.
4. **Follow the tech stack in PRD §9.1 exactly** (Node.js + TypeScript, `simple-git`, `diff`, Husky, DeepSeek API) — don't introduce new frameworks or swap libraries without asking first.

### Model note to flag, not resolve silently

The PRD's original design used two DeepSeek tiers: a fast model for triage and a stronger model for deep analysis + patching. The model actually available is **`deepseek-v4.1-flash`** (API model id), which now supports a native reasoning mode itself. Before Phase 4, ask me whether to:

- (a) keep the two-call design (flash-mode call for triage, reasoning-mode call for patch generation, same model, different mode flag), or
- (b) simplify to a single reasoning-enabled call per flagged hunk. Don't just pick one.

---

## Reference Files

| File | Purpose |
| --- | --- |
| `PRD.md` | Full requirements — scope, both modes, FR/NFR list, architecture |
| `src/prompts/security-agent-prompts.ts` | `SCAN_SYSTEM_PROMPT`, `PATCH_SYSTEM_PROMPT`, types (`ScanFinding`, `PatchSuggestion`), and prompt builder functions — already finished |

---

## Build Phases — work through these IN ORDER

### Phase 0 — Confirm Understanding

Before touching code: summarize your understanding of the project back to me in a few sentences, and list any ambiguities you found in `PRD.md`. Wait for my go-ahead.

### Phase 1 — Project Scaffold

- `npm init`, TypeScript config, folder structure per PRD §9.1: `src/prompts/`, `src/engine/local/`, `src/engine/remote/`, `src/hooks/`, `src/cli.ts`
- Install: `simple-git`, `diff`, `commander`, `inquirer`, `dotenv`
- **Done when:** `npm run build` compiles cleanly with stub modules, `codeguard --help` prints the command list (`scan`, `patch`, `config`).

### Phase 2 — Local Rule-Based Engine (FR-8)

- Regex detectors: hardcoded secrets, unsafe C functions (`strcpy`, `gets`, `sprintf`, `system`), raw/concatenated SQL
- **Done when:** Jest unit tests pass against a set of deliberately vulnerable code snippets you write as fixtures.

### Phase 3 — Git Hook Wiring (FR-2, FR-9)

- Husky pre-commit hook → capture `git diff --cached` → run Local Engine → block commit if severity exceeds configured threshold
- **Done when:** a real `git commit` in a scratch test repo actually triggers the hook and blocks a seeded-bad commit.

### Phase 4 — Remote AI Mode (FR-3, FR-4, FR-5, FR-6)

- Mode detector (API key present + reachable → Remote; else → Local fallback)
- Call `deepseek-v4.1-flash` using the prompts from `security-agent-prompts.ts` (resolve the model-note decision point first)
- Parse structured JSON output into `ScanFinding` / `PatchSuggestion`
- **Done when:** scanning a diff with a deliberate SQL injection returns a real structured finding + patch suggestion from the live API, AND disconnecting network / removing the API key falls back to Local Mode without crashing.

### Phase 5 — Patch Review & Apply Flow (FR-7)

- Inquirer prompt per finding: `[a]pply / [s]kip / [v]iew diff`
- Apply accepted patch to the actual file using the `diff` package
- **Done when:** accepting a suggested patch correctly modifies the file on disk and the diff is re-stageable.

### Phase 6 — Test Fixtures & End-to-End Test

- Seed a `test-fixtures/` mini-repo with known vulnerabilities (SQLi, hardcoded key, `strcpy`, raw query)
- Jest tests validating both `--local` and `--remote` modes against expected findings
- **Done when:** full test suite passes in both modes.

### Phase 7 — VS Code Extension (optional / stretch, only after Phase 6 is solid)

- Port CLI detection logic to VS Code Diagnostics + CodeAction API for inline quick-fix
- **Done when:** opening a file with a seeded vulnerability shows a squiggly + working "Apply CodeGuard Patch" quick fix.

---

## End-of-Phase Report (required after every phase)

Before moving to the next phase, report:

1. What was built (files touched)
2. How it was tested / verified
3. Any deviation from the PRD and why
4. Wait for explicit confirmation to continue
