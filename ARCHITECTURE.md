# CodeGuard — Architecture

CodeGuard is a pre-commit gate with two interchangeable engines behind one pipeline. This document explains
how the pieces fit, why the load-bearing decisions are shaped the way they are, and where the built system
deviates from the original PRD.

It is design-level. For a line-by-line trace of the code in execution order, read
[`docs/CODE_WALKTHROUGH.md`](docs/CODE_WALKTHROUGH.md). For the requirements, `PRD.md`. For using the tool,
[`README.md`](README.md).

---

## 1. The shape of the thing

```
   git commit
       │
       ▼
   .husky/pre-commit  or  .git/hooks/pre-commit        ← written by `codeguard install`
       │  (fails OPEN: a missing CLI or a crash allows the commit and shouts)
       ▼
   codeguard scan --staged   ──►  cli.ts                parse argv, choose streams, own the exit code
                                     │
                                     ▼
                             hooks/pre-commit.ts
                             runPreCommitCheck → getStagedDiff → scanDiff
                                     │
                       ┌─────────────┴─────────────┐
                       ▼                           ▼
                  engine/mode.ts             engine/diff.ts
                  decideMode()               parseDiff()  ← both engines stand on this
                       │
        ┌──────────────┴───────────────┐
        ▼                              ▼
  Local Mode                      Remote Mode
  engine/local/                   engine/remote/
  runLocalScan()                  runRemoteScan()
  regex rules                     ├─ budget.ts     exclude, then truncate (whole sections)
  detection only                  ├─ redact.ts     strip secrets BEFORE transmission
        │                         ├─ client.ts     Stage 1: whole diff, thinking OFF
        │                         ├─ context.ts    pick hunks, cap them, one call each
        │                         ├─ client.ts     Stage 2: per hunk, thinking ON
        │                         ├─ parse.ts      the answer is untrusted input
        │                         └─ reconcile.ts  the severity floor
        │                              │
        └──────────────┬───────────────┘
                       ▼
                engine/threshold.ts     findings + config → block / warn / allow
                       │
              ┌────────┴────────┐
              ▼                 ▼
       report/render.ts   report/file.ts
       stdout + stderr    .codeguard/report.json  (FR-12; feeds `patch --from-report`)
                       │
                       ▼
              exit 0 (clean) or 3 (blocked)
```

`codeguard patch` reuses the whole left-hand side: it runs the same `runPreCommitCheck`, then hands the
findings to `patch/`, and finally runs the check **again** so the verdict it returns is the real state of the
index rather than an assumption that the patches fixed things.

### The one structural decision everything else follows from

**The rule engine runs as a baseline in both modes.** `runLocalScan` is called once, before the branch, in
`scanDiff`. In Local Mode its output is the answer. In Remote Mode its output is used twice:

1. as the **severity floor** handed to `reconcile.ts`, and
2. as the **redaction floor** handed to `redact.ts` — the lines it flagged as hardcoded secrets are withheld
   from transmission regardless of whether the redaction patterns recognise their shape.

That single call site is why the two floors can be one principle (§4), why the fallback path after a
provider failure costs nothing extra, and why a Remote Mode scan can never report *less* than a Local Mode
scan of the same diff.

---

## 2. Remote Mode: the two-stage pipeline

### 2.1 The split, and what it buys

| | Stage 1 — triage | Stage 2 — deep analysis |
| --- | --- | --- |
| Scope | the whole diff (post-redaction, post-budget) | one flagged hunk |
| Reasoning | **off** | **on**, effort `high` |
| Requests | 1 | up to `remote.maxDeepAnalysisHunks` |
| Returns | `ScanFinding` — file, line_range, severity, category, one-sentence summary | `PatchSuggestion` — explanation, severity, `suggested_patch`, confidence |
| Purpose | find candidate problems cheaply | decide if each one is real, explain it, fix it |

Cost scales with **how suspicious the diff looks**, not with its size, and it is bounded by a number the
developer can reason about directly ("at most five extra AI calls per commit"). A large mechanical commit
costs one request. That is the whole reason the pipeline is two-stage rather than one call per finding or one
call for everything: a single deep-reasoning pass over the whole diff would be slower, costlier, and would
spend reasoning tokens on code with nothing wrong with it.

The bound is a **hunk count**, chosen over a token or dollar ceiling on purpose: it bounds worst-case latency
and spend together, needs no knowledge of provider pricing, and is directly observable in the output.

### 2.2 The thinking flag — the mechanism that implements the split

Both stages use **the same model id** (`deepseek-flash`). They differ by one request field:

```ts
const THINKING_ON  = { thinking: { type: 'enabled' }, reasoning_effort: 'high' } as const;
const THINKING_OFF = { thinking: { type: 'disabled' } } as const;
```

Four things about this that are easy to get wrong, all of them recorded in `engine/remote/client.ts`:

- **Thinking is ON by default at effort `high`.** Stage 1 therefore has to switch it *off explicitly*. A
  stage-1 request that merely omitted the field would silently be a reasoning call — inverting the entire
  cost design while looking perfectly correct in the source. There is no runtime symptom: the request
  succeeds, it is just expensive and mislabelled.
- **`buildRequestBody` is exported and pure so it can be asserted on directly.** The reasoning flag is the
  one place a wrong value is invisible at runtime and the one place this project cannot verify against the
  live API on demand — so it is tested as data, not as a side effect.
- **The fields go at the top level of the body.** With the official OpenAI SDK they must be passed inside
  `extra_body`; this client posts raw JSON, so they belong at the top level, which is what the provider's own
  request example shows.
- **`temperature`, `top_p`, `presence_penalty` and `frequency_penalty` are deliberately absent.** The
  provider silently ignores the first three in thinking mode and floors `top_p` at 0.95 — sending them would
  advertise a determinism this call does not have.

The client itself is a thin `fetch` wrapper with no SDK: the interface is one method (system + user prompt in,
text out), the request is a single JSON POST, and every dependency is one more place a credential could end
up logged. `LlmClient` is the seam NFR *Extensibility* asks for — swapping providers means writing one more
factory, because all of the provider-specific work lives in prompt construction and response parsing, which
are outside this module.

### 2.3 Preparation, in the order that matters

Before any request, `runRemoteScan` prepares the payload in a specific sequence:

```
excludePaths  →  redact  →  truncate to budget
```

- **Exclude first** so code from an excluded path is never redacted, transmitted, or reasoned about.
- **Redact second** so the budget is measured against what actually goes over the wire.
- **Truncate last**, dropping whole file sections from the **end** (the earliest staged changes are the most
  likely to be the point of the commit), always keeping at least the first file, and naming every file it
  dropped.

Whole sections only, never partial hunks: the model's line numbers are matched back to hunks, so a
structurally broken diff would not just look wrong, it would silently misplace answers.

Everything that was removed is reported as a note naming *what* was removed — excluded paths by name, files
the budget dropped, and a redaction count per file (**never** a value, never a line number).

### 2.4 Hunk selection

`engine/remote/context.ts` chooses which flagged hunks get the expensive call. One call per **hunk**, not per
finding: two findings on the same hunk are the same code to reason about, and charging twice would make the
cap lie about coverage. Selection is by severity first, diff order second (for stability), and split into
`selected` / `beyondCap` at the limit.

Findings that cannot be matched to any hunk (binary file, pure rename, invented path) are kept as
`unmatched` and still counted. Findings beyond the cap are **reported, not dropped** — a cap that truncates
silently is worse than no cap, because the developer would read a partial result as complete. The note names
the setting to raise.

### 2.5 Which answer wins

The precedence rules are stated in `engine/remote/index.ts` and they are not symmetric:

| Pair | Winner |
| --- | --- |
| Stage 2 vs Stage 1, for a hunk Stage 2 answered | **Stage 2** — including when its answer is "no, false positive" (an empty `suggested_patch`), which is why the second call is worth paying for. |
| Stage 1 alone, where Stage 2 never answered (capped, unmatched, failed) | **Stage 1** — the finding stands and still counts towards the threshold, without a patch. |
| The model vs the rule engine | **The rule engine.** The model's judgement replaces *its own* earlier judgement; it does not get to undercut a deterministic one. See §4. |

An empty patch is the *documented* false-positive signal from `PATCH_SYSTEM_PROMPT`, so it is a valid
outcome rather than a parse failure. It is the only outcome that removes a finding from the count, and the
explanation is kept so the report can still show what the model claimed. A finding that survives triage but
not deep analysis is exactly the noise the threshold should never see.

### 2.6 Failure handling, and the one failure worth retrying

The pipeline's provider failures are classified into four kinds — `transport`, `http`, `malformed`, `empty`
— and exactly one of them is retried, once:

- **`empty`** (a well-formed response with no message content) is retried. It is not a statement about the
  request, the credential or the endpoint, all of which are unchanged a second later. This came from a live
  run: deep analysis returned nothing, the scan degraded to triage-only findings as designed, and the
  identical call had succeeded minutes earlier on identical input. **The thing being bought is the patch.**
- **`transport`, `http`, `malformed` are not.** Repeating an unreachable call spends the timeout twice to
  reach the same conclusion; repeating a request the provider just rejected gets the same rejection.
- **The retry gets a fresh abort signal.** `AbortSignal.timeout` starts counting when it is created, so
  reusing the first attempt's signal would hand the retry whatever was left of the first attempt's budget.
  The signal is built by a thunk, per attempt.

Per-hunk failures degrade locally: a Stage-2 call that fails marks that hunk and every remaining one as
unpatched and stops the loop (a provider that just failed is likely to fail again), and a Stage-2 **parse**
failure is that hunk's problem alone. Findings already gathered are kept. Degrading all the way to Local Mode
would throw away real results to punish a partial outage.

A Stage-1 failure is different: without triage there is nothing at all to report, so the error propagates to
`scanDiff`, which falls back to Local Mode with the loud `THE AI CHECK DID NOT RUN` warning.

### 2.7 The model's output is untrusted input

`engine/remote/parse.ts` validates every field of every answer, because that answer becomes findings that can
block a commit and — in the patch flow — patches that get written to disk. *"The prompt asked for strict
JSON"* is not a guarantee.

Two deliberate asymmetries:

- **`category` is coerced, `severity` rejects the whole entry.** Category is a label; discarding a real
  vulnerability over a taxonomy typo is the worse outcome. Severity is a *decision input* — it is what the
  threshold compares against — so a guessed default either blocks a commit that should have passed or waves
  through one that should not.
- **A non-string `suggested_patch` is refused, not coerced to empty.** Coercing it would read as a confident
  "not a problem".

A file path that was not in the transmitted diff is rejected outright; a Stage-2 answer naming a *different*
file than the hunk it was asked about is rejected too, because that is the one substitution a
known-paths check cannot catch.

---

## 3. Reconciliation: the severity floor

`engine/reconcile.ts` exists because the two engines answer the same question differently and nothing used to
reconcile them. A diff the rule engine rates Critical — a string-concatenated query, unambiguous to a regex —
came back from the model as High. Same code, same bug, two different commit outcomes: Local Mode refused the
commit, Remote Mode warned and let it through.

That is not a parsing bug and not a bad model answer. It is an architectural gap: **a probabilistic judgement
was allowed to produce a weaker guarantee than a deterministic one, for a class of vulnerability the
deterministic engine already has a confident answer for.** For a tool whose promise is "guard, not linter",
which engine happens to be configured must not decide whether a known-bad commit is stopped.

### 3.1 The rule

- Remote reported that category in that file → each such finding's severity is **raised to at least** the
  rule engine's. **Never lowered.**
- The rule engine flagged a line Remote did not report → its finding is **added** at that line.
- Deep analysis dismissed it as a false positive → the dismissal is **overruled**, with a note quoting the
  model's own reasoning.

Remote Mode keeps everything worth paying for: it can raise a severity, and it can report categories the
rules cannot see at all. What it loses is the ability to be *quieter* than the regex engine about a class the
regex engine flags.

### 3.2 Category-level matching, exact-line merging — and why they differ

The two questions get opposite answers, and that is the subtle part:

| Question | Granularity | Because |
| --- | --- | --- |
| What is the severity floor? | **(file, category)** | Line numbers are not comparable between the engines. The rule engine reads a parsed diff and knows exactly which line it matched; the model reads the same diff as text and reports a range it inferred. Requiring agreement would mean choosing a line tolerance — a guess about model accuracy wearing the costume of a constant. |
| Is a rule match a separate finding? | **(file, line)**, exact equality | Both engines number lines in the new file, so equality means the same line. A range would absorb a rule match a line or two away — and since the model's line numbers are demonstrably approximate (a live run reported line 19 for a query at line 18), absorbing that would hide a real second instance of the same bug. |

The direction is settled by which mistake is worse: a missed floor is a silent downgrade (the bug this module
exists to fix), while a floor applied a little generously only raises the severity of a finding in a file
where the rule engine reports that exact category. The match is deliberately generous, and it still cannot
reach outside a category the rule engine flagged — the rules never emit `logic_bug`, `other`, or
`unhandled_exception`, so the categories only Remote Mode can find are never floored.

The per-line merge was itself a bug fix, found by watching the tool disagree with itself: with deep analysis
succeeding the report showed one consolidated finding, and with deep analysis failing — same diff — the
fallback produced three individual rows. **The output shape depended on whether Stage 2 happened to
succeed**, which is not something a developer should be able to observe. Merging per line makes the
successful path match the fallback path's granularity instead of losing information relative to it.

### 3.3 The notes

Every intervention is reported to stderr as plain text, phrased as a statement about what Remote Mode was
**not allowed** to do, and the reinstatement note has two shapes on purpose: *"the AI found none of this"*
and *"the AI found some of this and missed the rest"* call for quite different amounts of developer trust.
`reconcileWithBaseline` is a pure function; `remote/index.ts` calls it in one place (`finish()`), so every
return path from the pipeline — including the one that made no requests because the budget was empty —
passes through the floor.

---

## 4. The two floors are one principle

There are two places where a deterministic component overrules a probabilistic one, and they are the same
rule applied to different material:

| | Severity floor (`reconcile.ts`) | Redaction floor (`redact.ts` + `knownSecrets`) |
| --- | --- | --- |
| Deterministic input | the rule engine's `hardcoded_secret` / `sql_injection` findings | the rule engine's `hardcoded_secret` findings |
| Probabilistic counterpart | the model's severity judgement | the redaction pattern set |
| Effect | the model cannot report *lower* than the rules | the value cannot leave the machine even when no pattern matches |
| Failure prevented | a known-bad commit passing because AI was configured | a live credential reaching a third party |

**A confident, deterministic conclusion does not need a weaker heuristic's agreement before the tool acts on
its own answer.** That single sentence generates both.

The redaction floor's motivating case is measured, not hypothetical. On this tree, scanning a diff that
contains `const dbPassword = "Spr1ng2024!prod";`:

- the rule engine flags that line as a High hardcoded secret, **and**
- the redaction patterns alone walk straight past it — the identifier list needs `\bpassword\b` and there is
  no word boundary inside `dbPassword`, and the high-entropy backstop has a 20-character floor that a
  15-character value does not reach.
- so, on a diff-only scan, that value was transmitted in plaintext.

Lowering the 20-character floor would only have swapped one arbitrary threshold for another — it fails
identically on a 7-character secret. Threading the baseline finding through fixed it. Only the **category**
crosses the boundary, never the matched text.

Redaction is otherwise tuned with the opposite bias to the rules: a detection false positive blocks a commit
the developer did not deserve to have blocked, so the rules are precision-tuned; a redaction false negative
transmits a live credential, so the pass is recall-tuned. Better to mangle a harmless string than to leak a
real key.

### 4.1 The same principle, in three more places

Both floors are instances of a broader rule: **fail closed on security-relevant uncertainty, fail open on
operational error.** These are different questions, not an inconsistency between them.

**Fails closed** — doubt about what gets *written* or *transmitted*:

| Situation | Behaviour |
| --- | --- |
| `remote.hookMode` is an unrecognised value | falls back to `"local-only"`, **not** its own default `"auto"` — a typo there is somebody switching the AI scan off, and a wrong guess must land where nothing is transmitted |
| A rule-flagged secret has no locatable assignment on its line | the **whole line's content** is withheld rather than the line going out as written |
| A suggested patch contains a diff line that is not a diff line | refused, with the line number — not repaired |
| A patch's changed region falls outside the hunks it declares | refused; the message ends "CodeGuard did not write it" |
| A patch that parses and fits but changes nothing | refused — a suggested patch that is a no-op means something upstream is wrong |
| A file has mixed line endings | refused rather than normalised — a three-line fix must not become a whole-file diff |
| A patch path resolves outside the repository | refused; this is the write path |

**Fails open** — operational failure:

| Situation | Behaviour |
| --- | --- |
| Any unexpected error during a pre-commit scan | warning on stderr, **commit allowed**, exit `0` |
| A malformed `.codeguardrc.json` | defaults + `[CONFIG ERROR]` on every scan; never blocks |
| The scan report cannot be written | note + warning; the scan is unaffected |
| The hook cannot find the `codeguard` executable | three lines on stderr, **commit allowed** |

The asymmetry has one justification, stated where the policy is defined: failing closed on operational error
is safer in principle, but then a single bug blocks every commit in the repository until it is fixed, and a
gate that blocks on its own bugs is bypassed with `--no-verify` within a day and protects nothing
afterwards. The warning path is loud and repeats on purpose, so failing open is never *silent*. `codeguard
config --validate` exists because the hook deliberately does not block on a broken config — otherwise there
would be no way to ask whether the file is being read at all.

The CLI never calls `process.exit()`; it sets `process.exitCode` and returns, so Node flushes stdout. Exiting
hard would truncate the report the developer is being blocked by when stdout is a pipe — which is exactly the
situation in a hook.

---

## 5. Module responsibilities

| Path | Owns | Does not |
| --- | --- | --- |
| `src/cli.ts` | argv parsing, which stream each kind of text goes to, the process exit code, `install`/`config` output | know what a finding is |
| `src/exit-codes.ts` | the four codes, defined once | decide them |
| `src/severity.ts` | severity ordering, the type guard | any policy |
| `src/config/schema.ts` | `.codeguardrc.json` shape, defaults, validation, glob compilation | read files |
| `src/config/load.ts` | reading the config file; **never throws** | decide what a problem means |
| `src/git/repo.ts` | staged-diff capture, repo-root discovery, staging, hook-path discovery | parse the diff |
| `src/hooks/pre-commit.ts` | `scanDiff` (the check), `runPreCommitCheck` (the hook body), the installer | know either engine's internals |
| `src/prompts/security-agent-prompts.ts` | the two system prompts, their types, the prompt builders | call anything |
| `src/engine/diff.ts` | unified diff → files/hunks/lines with **new-side line numbers** | interpret content |
| `src/engine/findings.ts` | the finding shape both engines produce | — |
| `src/engine/mode.ts` | `.env` loading, the mode decision | make a request |
| `src/engine/threshold.ts` | findings + config → blocking / warned / allowed | print or exit |
| `src/engine/reconcile.ts` | the severity floor | touch the network |
| `src/engine/local/` | the rule set (FR-8), the scanner, comment detection | patch anything |
| `src/engine/remote/` | the two-stage pipeline, redaction, budget, provider client, parsing | render output |
| `src/report/render.ts` | human-readable findings, notes, verdict, config problems | write to a stream |
| `src/report/file.ts` | `.codeguard/report.json` — write, read back, gitignore entry | fail a scan |
| `src/patch/` | review prompt, patch parse/repair, apply, editor hand-off, `--from-report` | decide the verdict |

Three of these split out during the build rather than being planned, and the reason generalises: `cli.ts` and
`hooks/pre-commit.ts` would each have become a file with four unrelated reasons to change. `config/`, `git/`
and `report/` do not belong inside either. `patch/` arrived in Phase 5 as "one more thing to hang off
`cli.ts`" and became a directory because the review prompt, the patch parser, the apply step, the editor
hand-off and the report reader share one subject and no other module's. `report/` gained its second file in
the same phase for the report that `--from-report` reads back.

Rendering is pure string building: nothing in `report/render.ts` writes to a stream or reads the environment,
which keeps it directly assertable and leaves "where does this go" and "is colour appropriate" to the one
caller that can answer. `renderRemoteExtras` takes a structural parameter rather than the pipeline's outcome
type, so the renderer keeps no runtime dependency on the engine.

---

## 6. Where the design deviates from the PRD

### 6.1 The package layout grew (recorded in PRD §9.1.1)

§9.1's original sketch named `src/prompts/`, `src/engine/local/`, `src/engine/remote/`, `src/hooks/` and
`src/cli.ts`. The built tree adds `config/`, `git/`, `report/` and `patch/` — split by responsibility, for
the reason in §5. The PRD was updated to match rather than the code being bent to the sketch; §9.1.1 now
records the real layout and why it changed.

### 6.2 FR-12 landed early — in Phase 5, as a dependency rather than as polish

The PRD lists FR-12 (`.codeguard/report.json`) as **Could** priority, and its roadmap puts reporting late.
It was built in Phase 5 alongside FR-7, in the same commit as the patch review flow, because
`codeguard patch --from-report` needs a persisted scan to exist:

> a scan once paid for should be reviewable again without paying for it twice.

So the report is not decoration on top of the CLI — it is the storage half of a feature. Two consequences
that were designed in at that point rather than retrofitted:

- **The report holds `suggested_patch` text, which is a copy of the developer's own source**, so
  `codeguard install` adds `.codeguard/` to `.gitignore` additively (one line; an existing file is appended
  to, never rewritten) and reports what it did.
- **The report is versioned and validated on read**, not cast. A report from an older CodeGuard is a file
  full of plausible-looking fields that no longer mean what the reader thinks, and `--from-report` decides
  what gets written to the developer's files from that data.

### 6.3 Hook installation: Husky *and* native, chosen by detection

§5.1 says "via Husky or native `.git/hooks`", i.e. either. The built system supports both and picks
automatically, because the choice belongs to the repository, not to CodeGuard:

- **The rule is "write where Git will actually look."** The native path is resolved with
  `git rev-parse --git-path hooks/pre-commit`, which already accounts for `core.hooksPath` and linked
  worktrees — so a repository with a custom hooks directory is honoured rather than having a hook written
  somewhere Git ignores.
- **An empty `core.hooksPath` is treated as unset, and that is one case `--git-path` cannot answer.**
  `git config core.hooksPath ""` is degenerate — it is also a known way to try to switch hooks off — and
  Git honours it: `--git-path` answers `/pre-commit`, the filesystem root, so resolving it put the hook at
  `C:\pre-commit` and the installer's `mkdir` died with `EPERM` creating the root. For that value alone the
  path comes from `--git-common-dir` instead, which `core.hooksPath` cannot influence and which is the
  common dir rather than the per-worktree one — hooks hang off the former. The two answers agree in every
  case except this one, which is why the branch is scoped to it.
- **Husky is the one case needing special handling.** Husky v9 sets `core.hooksPath=.husky/_`, and
  `.husky/_/pre-commit` is a *generated shim* that sources the user-editable `.husky/pre-commit`; writing to
  the shim would be undone the next time Husky runs. So a Husky repository is written to `.husky/pre-commit`
  instead. Older Husky versions and hand-written setups point straight at `.husky`, so both shapes are
  accepted.
- **A `.husky/` directory that exists but is not active is correctly ignored** (no `core.hooksPath` means Git
  would not run a hook there).
- **Husky stays a devDependency of CodeGuard itself, not a requirement for users.** Requiring it would mean
  installing a tool to install a tool.

Two further install-time decisions worth recording, because they are about not surprising people: an
existing hook is moved aside and **called first** (appending would be simpler and wrong — a preserved hook
ending in `exit 0` would make anything after it dead code), and re-running is idempotent including the
backup from the first run (otherwise the user's original hook would silently stop running).

### 6.4 Mode detection checks presence, not reachability

FR-3 says to detect the mode from key presence **and reachability**. `engine/mode.ts` checks presence only,
deliberately: a pre-flight probe would cost a round trip on every scan and would still not prove the next
call succeeds. The first real call establishes reachability better than any probe, and the pipeline already
treats its failure as the fallback trigger per PRD §6.3.

**Presence chooses the attempt; the attempt decides the outcome.**

### 6.5 One model, two modes — replacing the original two-tier design

The PRD's original plan was two model tiers: a fast model for triage and a stronger one for deep analysis and
patching. The model actually available, `deepseek-flash`, supports a native reasoning mode, so the two-stage
design is implemented **with one model id and a per-request thinking flag** (§2.2). The cost design — cheap
broad pass, expensive narrow pass — is preserved exactly; only the mechanism for switching tiers changed.
PRD §6.1 and §9.1 were updated to describe it that way.

Related, and a correction rather than a deviation: the default model id was originally `deepseek-v4.1-flash`,
taken from documentation that was wrong for the account in use. The live API rejected it with a 400 listing
the names it does accept. The name is now `deepseek-flash`, and the lesson generalised into configuration —
see §6.7.

### 6.6 Out-of-scope items, still out of scope

- **FR-13 (user-defined rules)** is not implemented. Rules are declared as data in `engine/local/rules.ts`
  and the scanner accepts a `rules` override, so adding it is additive, but there is no config surface today.
- **FR-11 (VS Code extension)** is not built. It is Phase 7 of the build plan, and the CLI does not depend on
  it.
- **Patch generation remains Remote-Mode-only** (PRD §5.2), so `codeguard patch` in Local Mode reports the
  scan's verdict and says there is nothing to apply.

### 6.7 Configuration that fails in the safe direction

`remote.hookMode` deliberately breaks the fallback pattern every other setting in `config/schema.ts`
follows: an unrecognised value becomes `"local-only"`, which is **not** its default. A typo there is somebody
trying to stop their commits talking to a provider; falling back to `"auto"` would hand them exactly the
behaviour they were switching off, with only a warning banner between their code and the network.

The same reasoning produced `CODEGUARD_MODEL` and `CODEGUARD_BASE_URL`: a model id is a fact about an account
on an endpoint, not a fact about the provider, so it is a value to override in `.env` rather than one to
re-derive from documentation. Both are documented as *deliberate acts* — setting `CODEGUARD_BASE_URL` cannot
happen by accident, and the scan header still names the engine that ran.

---

## 7. Testing strategy, and the seams it required

The architecture is shaped by testability in three specific ways, all visible in the code:

**1. Both engines are driven from strings.** `scanDiff` takes a diff and a repo root and does no Git work
itself; `parseDiff` takes text. The whole Local Mode pipeline is unit-testable with no repository on disk,
and `codeguard scan --diff -` exposes the same property to users and CI.

**2. The provider is injectable.** `scanDiff` accepts an `environment` and a `client`, and `PreCommitOptions`
declares them so the forwarding contract is explicit rather than an accident of object spread. That is what
lets the Remote Mode e2e tests run the real HTTP client, real request body and real response parsing against
a local server (`CODEGUARD_BASE_URL`) instead of mocking at the module boundary.

**3. Jest never runs the tests un-type-checked.** `@swc/jest` only *strips* types, so `npm test` runs
`tsc -p tsconfig.test.json` first; that config re-includes `*.test.ts`, which the build config excludes.
Without that step the tests would be transpiled and never type-checked at all. `ts-jest` is not an option:
its peer range stops below this project's TypeScript 7.

Two testing decisions are load-bearing rather than incidental:

- **The mini-repo's `expected.json` was written by reading the fixtures, not by running the engine over
  them.** Expectations produced from the engine's own output would only ever detect *change*, never
  *wrongness*. Written independently, the table is meant to be wrong-able.
- **Remote Mode is tested against real recorded provider answers** (`test-fixtures/remote/`), replayed
  offline, with the test refusing to run against a different diff. A hand-written stub encodes what its
  author imagined the model returns; every defect found in this provider — the missing file header, the
  empty file name, the miscounted hunk — was found by looking at real output. The recorded set deliberately
  includes a case where the provider returned an empty answer and the retry succeeded, so the retry path is
  covered by a real trace rather than a synthetic one.

`jest.setup.ts` strips provider credentials from the environment before any test runs, so no test can reach
the live API and no test can accidentally spend money.

---

## 8. Unused ends, recorded so nobody "cleans them up"

Two fields are computed, returned and asserted in tests, but read by **no production caller**:

- `RemoteScanOutcome.notAnalysed` — built so the report could group findings that count without a patch.
  `scanDiff` does not put it on `ScanResult` and the renderer does not use it.
- `FlaggedHunk.lineMatched` — records whether a finding's line fell inside a hunk or was matched to the
  nearest one.

Neither is dead code left behind by accident: they are the plumbing for output that is not built yet, and
they are covered by tests. That also means the "counted but unpatched" findings are visible in the notes and
in the patch flow's per-candidate reasons, but not yet grouped as a block in the terminal report.
