# Recorded Remote Mode answers

These are real answers from the live provider, recorded so the Remote Mode tests
can be run without a network, an API key, or a bill. They are the reason the
remote tests are worth anything: a hand-written stub encodes what its author
imagined the model returns, and every defect found in this provider — the
missing file header, the empty file name, the miscounted hunk — was found by
looking at real output instead.

| File | What it is |
| --- | --- |
| `diff.patch` | The exact staged diff the answers were given |
| `triage.json` | The Stage-1 answer, verbatim, as a one-element array |
| `deep.json` | The Stage-2 answers, verbatim, in the order they were asked |
| `capture.cjs` | The tool that produced all three |

**Captured:** 2026-09-25, `deepseek-flash`, over `src/routes/users.js` and
`src/config.js` of the mini-repo. The test rebuilds that diff and refuses to
replay against a different one, so a fixture edit fails with "the answers were
recorded against a different diff" instead of a mapping error.

## What this particular recording contains

Worth knowing before reading a test failure, because none of it is incidental:

- **Triage flagged 3 issues**, two of them in `users.js`. It did *not* flag the
  credentials in `config.js`, which the local rule engine does — so this
  recording exercises `engine/reconcile.ts`'s floor: the AI is not allowed to
  return a weaker result than the rule engine for the same class of problem.
- **The first `config.js` answer came back empty**, and the pipeline retried it
  once. `deep.json` holds only the retry: an empty answer is delivered as a
  thrown `LlmError` of kind `empty`, so the capture's client never received a
  value to record. The replay client reproduces this by throwing on the first
  call, which is why its script is one entry longer than `deep.json`.
- **The retry declared the secrets a false positive**, with a well-reasoned
  explanation (the file says in its own comments that the values are fake). The
  floor kept them anyway. That is the correct outcome and it is asserted.
- **The `users.js` answer arrived well-formed** — correct file header, correct
  hunk counts, unlike every earlier sample. The repair logic stays, because the
  header defect is not fixed at the source; this recording just does not happen
  to need it.

## Refreshing

```
set -a; . ./.env; set +a
node test-fixtures/remote/capture.cjs
```

Review the new files before committing them: they are model output, and the only
thing standing between them and the repository is that the diff never carried a
real secret — which is the same guarantee the redaction pass makes, and the
reason `diff.patch` is safe to keep. It is the *unredacted* local diff, so the
fixtures' fake credentials appear in it. They are fake; the capture refuses to
run against anything else.
