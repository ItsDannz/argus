# The deliberately vulnerable mini-repo

This is a small support-ticket service, written the way a real one tends to be
written: one vulnerability class per file, each on a line a human can point at,
and a negative control beside it. It exists so that both engines can be run
against a whole repository rather than against a single file, and so that the
expectations live next to the code they describe in `expected.json`.

Every file here is load-bearing. Before editing one, read `expected.json` and
the comments in the file: the test asserts exact line numbers, rule ids and
severities, and a "harmless" tidy-up to a fixture shows up as a failing test
rather than as a silently weakened check.

| File | What it is for |
| --- | --- |
| `src/routes/users.js` | SQL injection by concatenation and by template interpolation |
| `src/routes/search.js` | A raw query assembled from a client-supplied column, and concatenation around a quoted value |
| `src/reports/export.py` | The Python spelling of the same problem: `%`-formatting and an f-string |
| `src/config.js` | Hardcoded credentials, next to the environment-variable form |
| `src/native/parse.c` | `strcpy`, `gets`, `sprintf`, `system` |
| `src/util/format.js` | Negative control: the same operations done safely |
| `src/app.js` | Negative control: ordinary wiring |

## Why there is no exploit syntax in this README

Both engines scan the diff, and a diff is text: an added line is an added line
whether it is code or prose. Writing the vulnerable snippets out here would mean
this file itself was reported — correctly, by the rules' own logic, and
uselessly for anyone reading it. So the summary above names the classes rather
than quoting them. The code is one directory away.

## How the tests use it

`src/__tests__/fixtures.e2e.test.ts` copies this tree into a scratch Git
repository, stages all of it, and scans the staged diff — so every line is an
addition and the run is exactly what a developer committing this service for the
first time would see. Nothing here is ever written to by CodeGuard.

## Refreshing the recorded Remote Mode answers

`../remote/` holds responses captured from the live provider (see the notes in
that directory). They are recorded against this exact tree: change a line here
and the triage answer stops lining up, which is a failing test rather than a
quiet drift.
