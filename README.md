# CodeGuard

**Autonomous Code Security Guard & Patch Agent** — a pre-commit security and logic-bug scanner for Git.

CodeGuard runs at `git commit` time, reads the **staged diff**, and reports security problems in the lines
you are about to commit. With a DeepSeek API key it also proposes a patch for each finding and can apply it
for you; without one it runs a self-contained rule engine offline, and everything still works.

It exists because the two common options are unsatisfying: CI scanners tell you about a vulnerability long
after you wrote it, and a `strcpy` grep cannot tell you whether the concatenated query in this specific
handler is exploitable. CodeGuard is a local gate on *only what you just changed*, with AI reasoning
available and optional.

- **Local Static Engine** — regex rules, no key, no network, milliseconds. Detection only.
- **Remote AI Mode** — DeepSeek, two-stage (triage then deep analysis), returns findings *and* patches.

This is a portfolio-grade DevSecOps + LLM tooling project, at **v0.1.0**. The CLI is complete through its
end-to-end test phase; the VS Code extension (FR-11) is not built. `PRD.md` is the requirements document.

---

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [What the output looks like](#what-the-output-looks-like)
- [The two operating modes](#the-two-operating-modes)
- [Configuration reference](#configuration-reference)
- [Environment variables](#environment-variables)
- [Exit codes](#exit-codes)
- [What is sent to the API](#what-is-sent-to-the-api)
- [Command reference](#command-reference)
- [Development](#development)
- [Known limitations](#known-limitations)

---

## Requirements

| | |
| --- | --- |
| Node.js | **>= 22.12.0** (`package.json` `engines`). 22.21.0 is what this is developed and tested on. |
| Git | Any recent version. CodeGuard shells out to `git`; it does not implement Git itself. |
| OS | Windows, macOS, Linux. The CLI, the hook script and the test suite are cross-platform. |
| API key | Optional. Only Remote AI Mode needs one. |

## Installation

The package is `private: true` and is not published to npm, so installation is from source:

```bash
git clone <this repository> codeguard
cd codeguard
npm install          # `prepare` runs `husky`, for CodeGuard's own development hooks
npm run build        # tsc -> dist/  (the CLI's bin entry points at dist/cli.js)
npm link             # puts `codeguard` on your PATH
```

`npm link` is what makes the bare `codeguard` command work. If you would rather not link globally, run it
through its path (`node /path/to/codeguard/dist/cli.js …`) or set `CODEGUARD_BIN` in the target repository
(see [Environment variables](#environment-variables)).

Then install the hook in the repository you want guarded:

```bash
cd /path/to/your-project
codeguard install
```

That writes a pre-commit hook — into `.husky/pre-commit` if the repository uses Husky, otherwise into
Git's own hooks directory (resolved with `git rev-parse --git-path`, so a custom `core.hooksPath` is
honoured; an empty `core.hooksPath` is treated as unset rather than as a directory) — and adds
`.codeguard/` to `.gitignore`, because the scan report contains patch text copied from your own source.

Two things `codeguard install` is careful about, both reported in its output:

- **An existing hook is never destroyed.** It is moved to `<hook>.codeguard-backup` and the script CodeGuard
  writes calls it first, so an existing `lint-staged` or test hook keeps running exactly as before.
- **Re-running is safe.** A second `codeguard install` updates the hook in place rather than nesting a
  second call, and does not orphan the backup from the first run.

One install case is a trap, and `install` warns about it rather than reporting a bare success. If
`core.hooksPath` is set to the empty string, the hook is written to Git's default location but **Git runs
nothing**: it honours the empty value itself and looks for the hook at the filesystem root. The install
still exits 0 — the file is correct and takes effect the moment the value is gone — but until then it prints
the dormancy warning on stderr, naming the command that clears it:

```
codeguard install: core.hooksPath is set to the empty string, so Git runs NO hook at any path.
  the hook at .git/hooks/pre-commit is dormant until that is cleared:
  git config --unset core.hooksPath
```

The installed hook resolves the executable as `CODEGUARD_BIN` → `./node_modules/.bin/codeguard` →
`codeguard` on `PATH`. If none is found it prints three lines of warning and **allows the commit** — see the
failure policy in [ARCHITECTURE.md](ARCHITECTURE.md).

## Quick start

### `codeguard install` — put the gate in place

```bash
codeguard install
# CodeGuard: installed pre-commit hook via native Git hooks (.git/hooks/pre-commit)
#   added .codeguard/ to .gitignore — the scan report holds patch text, not just findings
#   the hook runs: codeguard scan --staged
#   escape hatch:  git commit --no-verify
```

After this, `git commit` runs the scan automatically. Nothing else is required to get value from it.

### `codeguard scan` — run the check manually

```bash
codeguard scan                 # scan the Git index (what the hook runs)
codeguard scan --staged        # identical — the flag documents the default
codeguard scan --diff patch.diff   # scan a diff from a file, no repository needed
git diff --cached | codeguard scan --diff -   # or from stdin
codeguard scan --local         # force the rule engine
codeguard scan --remote        # force Remote AI Mode (errors without a key)
codeguard scan --no-color      # plain text output
```

Exit code `3` means it found something at or above your block threshold. `0` means clean. See
[Exit codes](#exit-codes).

### `codeguard patch` — review and apply the suggested fixes

```bash
codeguard patch                  # scan, then review each suggested patch interactively
codeguard patch --from-report    # reuse .codeguard/report.json instead of scanning again
codeguard patch --remote         # force an AI scan first
```

Per finding you choose from a four-option list. The question above it states the file, the line, the
severity, the category, the model's explanation, and whether the patch needed repair before it could be
offered:

```
?
  src/routes/login.js:7  Critical · sql_injection
  SQL assembled with string concatenation. Use a parameterised query /
  prepared statement so user input is bound as a parameter and can never be
  parsed as SQL.                                  ← the model's words, wrapped
  patch: the model's patch — 1 hunk
❯ [a] apply it to src/routes/login.js
  [e] edit the patch in vim
  [s] skip this finding
  [v] view the patch
```

When there is nothing to apply, the list is the same minus `[a]`, the status line reads `patch: no usable
patch`, a following line says **why** (`· no patch produced: …`), and `[e]` becomes *write a patch in
<editor>* — so a finding the model could not fix is still one edit away from a manual fix. Repaired patches
are announced here too (`· repaired: …`), not only when the repair happened.

It is an arrow-key list, so the letters are labels rather than keyboard shortcuts. Your editor comes from
`VISUAL`, then `EDITOR`, falling back to `vi` (`notepad` on Windows). Nothing is written to disk without an
explicit `apply`. Applied patches are written to your working tree **and staged**, then CodeGuard
**re-scans** and returns the new verdict — so the message you get at the end is the real state of the index,
not an assumption that the patch fixed things.

This command is interactive-only. On a non-TTY (CI, a pipe, an editor task) it refuses rather than hanging.

### `codeguard config` — see what is actually in effect

```bash
codeguard config             # show the resolved configuration and the mode that will be used
codeguard config --init      # write a starter .codeguardrc.json (refuses to overwrite an existing one)
codeguard config --validate  # exit 1 if the file is malformed, 0 otherwise
```

Real output from this repository:

```
CodeGuard configuration
  config file    C:\codeguard\.codeguardrc.json
  block on       Critical
  warn on        High
  exclude paths  src/engine/local/rules.ts, test-fixtures/**, **/__tests__/**, src/prompts/security-agent-prompts.ts
  model          the built-in default
  hook mode      local-only
  mode           local rule engine (forced by remote.hookMode = "local-only")
  deep hunks     up to 5 per scan
```

The `mode` line names the **cause**, not just the outcome — because "why did my commit just make a network
call?" and its inverse, "why is it not using the key I set?", are the two questions this line exists to
answer before they are asked.

## What the output looks like

Real output, from scanning a diff that introduces a hardcoded key and a concatenated query
(`scan --diff … --local --no-color`):

```
CodeGuard (local engine): 2 issues in 1 file

  src/routes/login.js

        4  High      hardcoded-secret-assignment
        Possible hardcoded credential. Load it from an environment variable
        or a secrets manager and rotate the value if it was ever real
        (FR-10).

        7  Critical  sql-string-concatenation
        SQL assembled with string concatenation. Use a parameterised query /
        prepared statement so user input is bound as a parameter and can
        never be parsed as SQL.

Commit blocked: 1 issue at or above the block threshold "Critical".
  Found: 1 Critical, 1 High.

Fix the issues above, then stage the fixes and commit again.
To commit anyway:  git commit --no-verify
```

Findings go to **stdout**; notes, warnings and progress go to **stderr**, so `codeguard scan --diff - >
report.txt` gives you just the findings.

The header names the engine that ran. That matters: the two modes give different guarantees, and a result
from the rule engine can never include an AI patch.

## The two operating modes

### Local Static Engine (no API key, no network)

A curated rule set matched against the added lines of the diff. Detection only — PRD §5.2 puts patch
generation out of scope for Local Mode.

| Category | What is detected | Severity |
| --- | --- | --- |
| `hardcoded_secret` | Key-shaped identifier assigned a string literal (≥ 6 chars, not a placeholder); AWS `AKIA`/`ASIA` access key ids; PEM private key headers | High / Critical |
| `sql_injection` | SQL verb inside a quoted string followed by `+`; template-literal interpolation; Python f-strings; `%`-formatting; `str.format()` | Critical |
| `unsafe_c_function` | `strcpy`, `gets`, `sprintf` (C family files only) | High / Critical |
| `command_injection` | `system(` — in any language | Critical |
| `code_execution` | `eval(`, `new Function(`, Python `exec(` | High |
| `insecure_crypto` | MD5, SHA-1 (Medium — fine for checksums); DES, ECB mode (High) | Medium / High |

Rules are declared as data in `src/engine/local/rules.ts`, one object each, with the severity and the
remediation text attached. Placeholder values (`changeme`, `your_api_key`, `<YOUR_KEY>`, `${KEY}`, `%s`,
masks like `xxxxx`) are deliberately not flagged — a secret scanner that cries wolf about documentation is
one people switch off.

### Remote AI Mode (DeepSeek API key required)

Two stages over the same model, separated by a per-request **thinking flag** — this split is the cost
design, not an architectural flourish:

1. **Triage** — the whole diff, reasoning **off**. One request. Returns findings with one-sentence
   summaries. A regex cannot see a logic bug or a business-context flaw; this can.
2. **Deep analysis** — one request **per flagged hunk**, reasoning **on**. Returns the explanation, the
   confidence, and a `suggested_patch`, or an empty patch to say "this was a false positive".

Cost therefore scales with *how suspicious the diff looks*, not with its size, and is bounded by
`remote.maxDeepAnalysisHunks`. Everything that was not analysed is still reported — truncation is never
silent.

Full mechanism, including the thinking flag and the retry policy: [ARCHITECTURE.md](ARCHITECTURE.md).

### How the mode is chosen

| # | Condition | Result |
| --- | --- | --- |
| 1 | `--local` and `--remote` together | error |
| 2 | `--local` | Local — even with a key present |
| 3 | `--remote` | Remote, or an **error** if no key |
| 4 | no `DEEPSEEK_API_KEY` | Local (the supported default, PRD §6.3) |
| 5 | `remote.hookMode: "local-only"` | Local, key or no key |
| 6 | otherwise | Remote |

Configuration decides what happens **by default**; the command line decides what happens **now**. Steps 5
and 6 are the only ones a config file can move, and they sit below the flags on purpose: a committed file
must not be able to overrule a developer who just typed `--remote`. `"local-only"` therefore does not
*disable* Remote Mode — `codeguard scan --remote` still performs an AI scan.

`--remote` with no key is an error rather than a silent fallback. A rule-based scan when the flag implied an
AI one would misreport what actually ran.

**If a remote call fails** (no network, 401, timeout), the scan falls back to the rule engine and says so in
exactly those terms:

```
[CODEGUARD] Remote AI Mode failed, so the AI check DID NOT RUN.
```

A clean local result after a failed AI call is not a clean AI scan, and the message is written so that it
cannot be misread as one. The commit is allowed in that case — an operational failure is not a finding.

## Configuration reference

`.codeguardrc.json` at the repository root. Every key is optional; anything missing uses the default. The
file is read fresh on every scan (there is no cache to invalidate).

```json
{
  "threshold": {
    "blockOn": "Critical",
    "warnOn": "High"
  },
  "excludePaths": ["dist/**", "vendor/", "**/*.generated.ts"],
  "remote": {
    "maxDeepAnalysisHunks": 5,
    "timeoutMs": 60000,
    "hookMode": "auto"
  },
  "model": "deepseek-flash"
}
```

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `threshold.blockOn` | `"Critical" \| "High" \| "Medium" \| "Low"` | `"Critical"` | Findings at or above this severity **block the commit** (exit `3`). |
| `threshold.warnOn` | one of the four | `"High"` | Findings at or above this severity, but below `blockOn`, are reported and allowed through. |
| `excludePaths` | `string[]` | `[]` | Glob patterns. A matching file is skipped entirely — in Remote Mode it is never transmitted. |
| `remote.maxDeepAnalysisHunks` | integer ≥ 0 | `5` | How many flagged hunks may get a Stage-2 reasoning call. **`0` is valid**: triage only, no patches, one API call. |
| `remote.timeoutMs` | integer ≥ 1 | `60000` | Per-request timeout, applied to each API call separately. |
| `remote.hookMode` | `"auto" \| "local-only"` | `"auto"` | Whether an **automatic** scan (i.e. the hook) may choose Remote Mode. `--remote` overrides it. |
| `model` | non-empty string | built-in default | Model id, if you need a different one. Overridden by `CODEGUARD_MODEL`. |

`blockOn` / `warnOn` are severity **floors**, not exact matches: `blockOn: "High"` blocks High *and*
Critical. Setting `warnOn` above `blockOn` is redundant rather than wrong — everything at `warnOn` already
blocks, so the stricter threshold wins and no warning is ever printed. The defaults block on Critical only,
which is the least surprising state for a repository that has never opened this file.

### `excludePaths` glob syntax

Deliberately a subset, hand-rolled to keep the dependency list at what PRD §9.1 names:

| Pattern | Matches |
| --- | --- |
| `*` | any run of characters within one path segment |
| `**` | any run of characters across segments |
| `?` | exactly one character within a segment |
| `node_modules` (no `/`) | that name at any depth — the directory and everything under it |
| `dist/**` (has a `/`) | anchored to the repository root |

**Not supported:** `!` negation and `[abc]` character classes. A trailing `/` is treated as `/**`
(`vendor/` means everything inside `vendor`). Backslashes are normalised to `/`, so a config written on
Windows behaves the same on macOS and Linux.

This repository's own `.codeguardrc.json` is a working example — it excludes the rule definitions and the
deliberately vulnerable fixtures, because a security tool scanning its own rule table reports itself:

```json
{
  "threshold": { "blockOn": "Critical", "warnOn": "High" },
  "remote": { "maxDeepAnalysisHunks": 5, "timeoutMs": 60000, "hookMode": "local-only" },
  "excludePaths": [
    "src/engine/local/rules.ts",
    "test-fixtures/**",
    "**/__tests__/**",
    "src/prompts/security-agent-prompts.ts"
  ]
}
```

### When the config file is wrong

A malformed config **never blocks a commit**. Problems are printed to stderr as `[CONFIG ERROR]` text on
every scan and the defaults are used, because a gate that refuses commits over a JSON typo gets bypassed
with `--no-verify` and then protects nothing. `codeguard config --validate` is the way to ask directly; it
exits `1` for a malformed file.

Two behaviours worth knowing:

- **Unknown keys are reported, not ignored.** `"excludePath"` (singular) is a plausible typo, and silently
  ignoring it would leave you believing a path was excluded when it was not.
- **An unrecognised `remote.hookMode` falls back to `"local-only"`, which is not its default.** A typo like
  `"local_only"` is somebody trying to stop their commits talking to a provider, and falling back to
  `"auto"` would hand them exactly the behaviour they were switching off. Every other invalid value falls
  back to its own default; this one intentionally does not, so a wrong guess lands on the side where no code
  leaves the machine.

## Environment variables

`.env` in the repository root is read (never written) and merged **under** the process environment, so an
explicitly exported variable always wins over a stale file in a checkout. A missing `.env` is the normal
case and is not an error.

| Variable | Purpose |
| --- | --- |
| `DEEPSEEK_API_KEY` | The API key. Absent or blank means Local Mode. Never logged; never written to any file CodeGuard produces. |
| `CODEGUARD_MODEL` | Overrides the model id. Strongest of the three model sources: `CODEGUARD_MODEL` > config `model` > built-in default. Exists so a wrong id is a one-line `.env` fix rather than a code change. |
| `CODEGUARD_BASE_URL` | Points the client at a different endpoint (self-hosted gateway, or a local server for testing the real HTTP path). Must be set explicitly; nothing else can redirect a diff. |
| `CODEGUARD_BIN` | Used by the **installed hook script**, not by the CLI: the executable to run when `codeguard` is neither on `PATH` nor in `./node_modules/.bin`. |
| `NO_COLOR` | Set and non-empty disables colour, like everywhere else. `--no-color` also works, and colour is off automatically when stdout is not a terminal. |

`.env.example` in this repository is the template:

```bash
cp .env.example .env
# then set DEEPSEEK_API_KEY=...
```

`.env` is gitignored in this repository and must never be committed (FR-10).

Changing the model id: the built-in default is `deepseek-flash`. A model id is a fact about *your account on
*this endpoint*, not a fact about the provider — an earlier default (`deepseek-v4.1-flash`) was taken from
documentation that was wrong for the account in use and was rejected by the API with a 400 listing the names
it does accept. If a scan starts failing that way, put one of the listed names in `CODEGUARD_MODEL` or the
config `model` key.

## Exit codes

The exit code is a contract with the hook and with anything wrapping the CLI. `BLOCKED` and `ERROR` both
refuse a commit — Git treats every non-zero code as "refuse" — but they mean different things, and merging
them would make "the scan found a Critical" indistinguishable from "the tool could not run".

| Code | Name | Meaning |
| --- | --- | --- |
| `0` | `OK` | The scan completed and found nothing at or above `blockOn`. Also returned when an operational failure was allowed through by design (see below). |
| `1` | `ERROR` | CodeGuard itself could not run: not a Git repository, `--remote` with no key, a malformed config on `config --validate`, `config --init` when the file already exists, an unexpected internal error. |
| `2` | `NOT_IMPLEMENTED` | Reserved in `src/exit-codes.ts` for a command that exists but is not built. **Currently unused** — every command is implemented. |
| `3` | `BLOCKED` | The scan completed and found at least one issue at or above `blockOn` (FR-9). |

By design, an **internal** failure during a pre-commit scan returns `0` and shouts on stderr rather than
blocking your commit. The reasoning is in [ARCHITECTURE.md](ARCHITECTURE.md); the short version is that a
gate which blocks on its own bugs gets permanently bypassed.

> **A blocked `git commit` exits `1`, not `3`.** The codes above are the *CLI's* contract. When the hook
> exits non-zero, Git reports the whole commit as failed and uses its own code for that. So if you are
> scripting around `git commit`, branch on failure, not on `3` — `3` is what `codeguard scan` returns, and
> what you would see from the CLI directly.

## What is sent to the API

Remote Mode sends **the diff, and only the diff** (FR-4) — never a whole file, and never any content from
outside the staged changes. There is no "surrounding context" option, deliberately: the only other source of
context is your working tree, and sending code you did not stage is exactly the exposure a diff-only rule
exists to prevent. Git's three lines of context either side of each change are already part of the diff.

Before transmission, and with no flag to turn it off:

- **A redaction pass strips secret-shaped values.** Published credential formats (AWS, GitHub, Slack,
  OpenAI, Google, Stripe, JWT, npm), credentials embedded in URLs, values assigned to secret-naming
  identifiers, and a high-entropy backstop for credentials whose format nobody has published.
- **Anything the rule engine already flagged as a hardcoded secret is withheld** even if every pattern
  above walks past it. A confident, deterministic answer is not required to have a weaker heuristic's
  agreement before the tool acts on it.
- Values are replaced with a loud placeholder (`«REDACTED:aws-access-key»`) **in place**, so the line count
  and the diff structure survive. A patch that would quote a redacted value is withheld rather than shown,
  because applying it would write the placeholder into your file.
- What was removed is reported **by file and kind only** — never the value, never the line number.

Redaction is a guard rail, not a licence: **do not commit secrets and rely on this pass.** See
[Known limitations](#known-limitations) for what it does not catch.

The API key itself never reaches a finding, a note, an error message or the report. The request is built
with the key in a header, and client error messages are run through a redaction function before they are
stored, so even a provider that echoed the credential back could not get it printed.

## Command reference

```
codeguard <command> [options]
```

| Command | Options |
| --- | --- |
| `scan` | `--staged` (the default), `--diff <file>` (`-` for stdin), `--local`, `--remote`, `--no-color` |
| `install` | *(none)* |
| `patch` | `--from-report`, `--local`, `--remote`, `--no-color` |
| `config` | `--init`, `--validate` |

`codeguard scan --diff` needs no repository: it reads a diff from a file or stdin and scans it. That is how
this project's own tests exercise the whole pipeline against a fixture, and it works in CI on a pull
request's patch.

`codeguard patch --from-report` reads `.codeguard/report.json` (written by the last scan) instead of
scanning again — useful when the scan already happened, and it costs no API call. It skips the closing
re-scan, since nothing was re-scanned.

## Development

```bash
npm test          # build + type-check + jest  (the full gate)
npm run test:unit # type-check + jest, skipping the process-spawning e2e suites
npm run build     # tsc -p tsconfig.json      -> dist/
npm run typecheck # tsc -p tsconfig.test.json (includes the tests, which the build excludes)
npm run clean     # remove dist/
```

`npm test` is three steps, and the middle one is not optional: Jest runs through `@swc/jest`, which only
*strips* types, so the tests are not type-checked as they run. `tsc -p tsconfig.test.json` does that
separately, and it re-includes the `*.test.ts` files that the build config excludes — without it, the tests
would never be type-checked at all. `ts-jest` is not used because its peer range stops below this project's
TypeScript 7.

Current state: **515 tests in 31 suites, all passing** (measured on this tree).

`jest.setup.ts` strips provider credentials from the environment before any test runs, so no test can reach
the live API. Remote Mode is tested against recorded real answers instead:

| Path | What it is |
| --- | --- |
| `test-fixtures/local-engine/` | Small per-rule snippets, positive and negative. |
| `test-fixtures/mini-repo/` | A deliberately vulnerable support-ticket service, one vulnerability class per file, with a negative control beside it. `expected.json` states exactly what the engine must report — **written by reading the fixtures, not by running the engine over them**, so it can be wrong in a way that detects wrongness rather than mere change. |
| `test-fixtures/remote/` | Real provider answers (`triage.json`, `deep.json`) recorded against an exact diff (`diff.patch`), replayed offline. They are the reason the Remote Mode tests are worth anything: a hand-written stub encodes what its author imagined the model returns, and every defect found in this provider — the missing file header, the empty file name, the miscounted hunk — was found by looking at real output. |

To re-record the remote fixtures you need a live key:

```bash
set -a; . ./.env; set +a
node test-fixtures/remote/capture.cjs
```

Read `test-fixtures/remote/README.md` before committing new output; it documents what the current recording
contains and why.

## Known limitations

Documented honestly, with the boundaries stated as they actually behave. Where a claim is specific it was
measured against this build rather than inferred from the source.

### 1. SQL detection is a set of regexes, and it has boundaries

The rule needs a **SQL verb inside a quoted string, on the same added line**. Measured against a diff
containing the same query in six spellings, `scan --local` reported exactly two of them:

| | Added line | Reported |
| --- | --- | --- |
| 1 | `const sql = "SELECT * FROM users WHERE a = '" + a + "'";` | ✅ `sql-string-concatenation` |
| 2 | ``const sql = `SELECT * FROM users WHERE id = ` + id;`` | ❌ template literal, concatenated rather than interpolated |
| 3 | `const sql = "SELECT * FROM users";`<br>`  + " WHERE id = " + id;` | ❌ the `+` starts the next line; analysis is per line |
| 4 | `const sql = base + " WHERE id = " + id;` | ❌ no SQL verb in any literal — built from a variable |
| 5 | `const sql = "SELECT * FROM t WHERE x = %s" % args;` | ✅ `sql-percent-format` |

So: a query assembled entirely from variables, built by a query builder or an ORM, split so the verb and the
operator land on different lines, or written as a template literal with `+` instead of `${}`, is **not**
detected. Rows 2 and 3 are real misses of an exploitable query, not hypotheticals.

Related, and by design: comments are skipped only when they are **whole-line** comments (`//` at the start
of a line, `#` in languages where that is a comment). A trailing comment on a line of code is still
scanned, and block comments are not tracked at all — both need real parsing. The default for an unknown file
extension is to skip nothing, so an unrecognised file is scanned conservatively rather than silently
ignored.

### 2. Redaction is best-effort, and its residual is a specific shape

The pass catches published credential formats and secret-named assignments. Measured against a diff
containing five candidate secrets, it withheld one on its own:

| | Added line | Withheld |
| --- | --- | --- |
| 1 | `const aws = "AKIAIOSFODNN7EXAMPLE";` | ✅ `aws-access-key` (named pattern) |
| 2 | `const dbPassword = "Spr1ng2024!prod";` | ❌ on its own — **✅ via the rule engine floor** |
| 3 | `const endpointKey = "x9f2k1p7";` | ❌ |
| 4 | `DB_PASS=supersecret123` | ❌ |
| 5 | `password: hunter2xyz` | ❌ |

What is left after the floor, in one sentence: **a credential that has no published format, is not assigned
to an identifier the patterns recognise, and whose line the rule engine did not flag either.**

The recurring causes for rows 3–5:

- **Unquoted values.** Every assignment-shaped pattern requires a quote, so `DB_PASS=supersecret123` and
  `password: hunter2xyz` (YAML, `.env` blocks) are invisible to it.
- **Identifiers with no word boundary where the pattern expects one.** Row 2 (`dbPassword`) is the case the
  rule engine saves: the identifier list matches on `\bpassword\b`, and there is no boundary inside
  `dbPassword`, so the patterns alone miss it.
- **Values under 20 characters on a line that names no secret.** Rows 3 and 4. The high-entropy backstop
  requires a secret-naming word on the same line *and* a 20+ character quoted value; the floor exists
  because lowering that number only swaps one arbitrary threshold for another.

**Treat the pass as a guard rail, not a guarantee.** It is there so that an accidental credential in a diff
does not become an accidental disclosure; it is not a reason to stage one.

### 3. Remote Mode line numbers are approximate

A Local Mode finding's line is exact — the rule engine matches a specific line of the parsed diff. A Remote
Mode finding carries the line **the model reported**, and model line numbers are demonstrably approximate: a
live run reported line 19 for a query the file has on line 18. That number is what gets displayed.

Two consequences, both deliberate choices rather than oversights:

- A remote finding can be shown one or two lines off from where you would have pointed. The explanation
  names the query, so the finding is still actionable.
- Reconciliation matches rule findings to AI findings **by exact line equality**, not by a range. A range
  would absorb a rule match a line or two away, and since rule findings are the *exact* ones, that would
  hide a real second instance of the same bug. A near-duplicate row is the cheaper mistake.

Patch placement does **not** depend on the model's line numbers: patches are applied by matching content, not
by line offset (see below).

### 4. Model-authored patches are frequently malformed, and CodeGuard repairs or refuses them

The provider does not reliably emit valid unified diffs. Two defects are on record from real samples:

- **Hunk headers whose stated line counts disagree with the body** (`@@ -11,2 +11,2 @@` over two removed
  lines and one added line). This is **fatal** if taken at face value: `parsePatch` rejects the whole patch,
  so the developer sees a finding they cannot fix with one keystroke. CodeGuard **recounts every hunk from
  its body and ignores the header's numbers entirely** — the body is the patch, and the counts are a claim
  about it that can be checked rather than believed.
- **No `--- a/…` / `+++ b/…` file header at all.** Non-fatal for the applier, but added anyway from the path
  the *finding* names, so a patch leaving CodeGuard is a complete file diff that also works with `git apply`.

The repair is announced, not silent — if a patch was rewritten, you are told which hunk and what the counts
became before you are asked to approve it.

What is **refused** rather than guessed at: a body line that is not a diff line (`...` where code was
elided, a stray comment, prose). The refusal names the line number and quotes the text. Guessing there is
how a patch silently edits the wrong thing, and that is the one failure mode this tool cannot recover from.

This defect is not fixed at the source — the repair logic stays because the model still produces these
patches, and the recorded fixtures from the most recent capture happen not to need it.

### Other residuals

- **Only the index is scanned.** Unstaged work in your working tree is invisible to `scan` and to the hook
  (that is what `git diff --cached` means). `patch` stages what it applies precisely so the re-scan sees it.
- **Local Mode never generates patches.** Detection only, by scope (PRD §5.2). `codeguard patch` says so and
  exits with the scan's verdict.
- **FR-13 (user-defined rules) is not implemented.** Rules are declared as data internally, so adding it is
  additive, but there is no config surface for custom rules today.
- **FR-11 (VS Code extension) is not built.** Phase 7 of the build plan; nothing in the CLI depends on it.
- **Exit code `2` is defined but unused** (see [Exit codes](#exit-codes)).
- **`remote.hookMode` is per-repository, not per-developer.** A committed `local-only` applies to everyone
  who clones, which is the point — but it also means a teammate cannot opt into AI scans without the
  `--remote` flag or their own config.
- **A `--remote` scan costs real money**, bounded by `maxDeepAnalysisHunks` and `timeoutMs` but not by a
  dollar ceiling. `maxDeepAnalysisHunks: 0` is the cheapest useful Remote Mode: one triage call, no patches.
- **`codeguard patch` is interactive only**, so it cannot be scripted or run in CI.

---

## Documentation map

| File | For |
| --- | --- |
| `README.md` | This file — using the tool. |
| `ARCHITECTURE.md` | The design: the two-stage pipeline, the two floors, reconciliation, and where it deviates from the PRD. |
| `docs/CODE_WALKTHROUGH.md` | Reading the source: a line-by-line trace of both commands in execution order. |
| `PRD.md` | The requirements (FR-1…FR-13, §9 architecture, §9.1 stack). |
| `test-fixtures/remote/README.md` | What the recorded provider answers contain, and how to refresh them. |
| `test-fixtures/mini-repo/README.md` | What each vulnerable fixture is for. |

> **Note for this repository's own checkout:** `docs/CODE_WALKTHROUGH.md` is listed in `.gitignore` under
> "Docs kept local only, not pushed" (line 29) — it exists on disk but will not be committed, because it is
> a working reference for reading the source rather than published documentation. `README.md` and
> `ARCHITECTURE.md` are tracked: they are what someone landing on this repository cold gets. `git add` for
> the walkthrough therefore needs `-f`; the other two do not.
