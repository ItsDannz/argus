/**
 * Mode selection as it reaches the hook, and the fallback (FR-3, PRD §6.3).
 *
 * The remote engine has its own tests; what is verified here is the INTEGRATION
 * — that the hook asks the right question, prints results under the right engine
 * label, and degrades in the right direction when the provider is unreachable.
 * The Phase 4 acceptance criterion is exactly that last one: "disconnecting
 * network / removing the API key falls back to Local Mode without crashing".
 *
 * The provider is stubbed and the environment injected throughout, so nothing
 * here can reach the network or depend on what happens to be exported in the
 * shell that runs the tests.
 */

import { describe, expect, it } from '@jest/globals';

import type { Environment } from '../../engine/mode';
import { API_KEY_VAR } from '../../engine/mode';
import { LlmError, type LlmClient } from '../../engine/remote';
import type { LlmRequest } from '../../engine/remote/client';
import { EXIT } from '../../exit-codes';
import { scanDiff } from '../pre-commit';

const KEY = 'sk-live-9f2b7c41d8e35a60b4c7f1e2';
const REPO_ROOT = '/nowhere/scratch-repo';

/**
 * A SQL injection the LOCAL rules also detect, so a fallback is observable.
 *
 * The shape is load-bearing. `sql-string-concatenation` matches a quoted string
 * containing a SQL verb immediately followed by `+`, and its character class
 * excludes both quote types — so the more natural `"...name = '" + name + "'"`
 * does NOT match, because the embedded apostrophe ends the class early. That is
 * a pre-existing gap in the Phase 2 rule, reported rather than papered over
 * here; this fixture uses the shape the rule does cover.
 */
const SQLI_DIFF = [
  'diff --git a/src/db.js b/src/db.js',
  'new file mode 100644',
  'index 0000000..1111111',
  '--- /dev/null',
  '+++ b/src/db.js',
  '@@ -0,0 +1,3 @@',
  '+function findUser(db, name) {',
  '+  const sql = "SELECT * FROM users WHERE name = " + name;',
  '+  return db.query(sql);',
  '+}',
  '',
].join('\n');

/** A change the regex rules cannot see at all. */
const CLEAN_DIFF = [
  'diff --git a/src/math.js b/src/math.js',
  'index 1111111..2222222 100644',
  '--- a/src/math.js',
  '+++ b/src/math.js',
  '@@ -1,2 +1,3 @@',
  ' const add = (a, b) => a + b;',
  '+const sub = (a, b) => a - b;',
  ' const mul = (a, b) => a * b;',
  '',
].join('\n');

function environmentWith(env: NodeJS.ProcessEnv): Environment {
  return { env, envFile: null, fromFile: [] };
}

const WITH_KEY = environmentWith({ [API_KEY_VAR]: KEY });
const WITHOUT_KEY = environmentWith({});

const TRIAGE_HIT = JSON.stringify({
  findings: [
    {
      file: 'src/math.js',
      line_range: [2, 2],
      severity: 'Critical',
      category: 'logic_bug',
      summary: 'subtraction changes existing behaviour',
    },
  ],
});

/** A diff carrying a live-looking credential, to exercise the redaction note. */
const SECRET_DIFF = [
  'diff --git a/src/config.js b/src/config.js',
  'new file mode 100644',
  'index 0000000..3333333',
  '--- /dev/null',
  '+++ b/src/config.js',
  '@@ -0,0 +1,1 @@',
  '+const API_KEY = "sk-live-9f2b7c41d8e35a60b4c7f1e2";',
  '',
].join('\n');

const PATCH = JSON.stringify({
  file: 'src/math.js',
  line_range: [2, 2],
  severity: 'Critical',
  category: 'logic_bug',
  explanation: 'This looks like it should be addition.',
  suggested_patch: '--- a/src/math.js\n+++ b/src/math.js\n@@ -1,3 +1,3 @@\n-const sub = (a, b) => a - b;\n+const sub = (a, b) => a + b;',
  confidence: 'high',
});

/** Records what it was asked, and answers from canned text. */
function stubClient(answers: { triage: string | Error; patch?: string | Error }): LlmClient {
  const requests: LlmRequest[] = [];
  return {
    model: 'stub-model',
    complete: async (request: LlmRequest): Promise<string> => {
      requests.push(request);
      if (request.system.includes('triage engine')) {
        if (answers.triage instanceof Error) throw answers.triage;
        return answers.triage;
      }
      const patch = answers.patch ?? PATCH;
      if (patch instanceof Error) throw patch;
      return patch;
    },
  };
}

/** Captures what the scan wrote, so the report text can be asserted on. */
function capture(): { io: { write: (t: string) => void; writeError: (t: string) => void }; out: () => string; err: () => string } {
  const stdout: string[] = [];
  const stderr: string[] = [];
  return {
    io: { write: (text) => void stdout.push(text), writeError: (text) => void stderr.push(text) },
    out: () => stdout.join(''),
    err: () => stderr.join(''),
  };
}

describe('scanDiff — Local Mode is the keyless default', () => {
  it('runs the rule engine when no key is available', async () => {
    const { io, out } = capture();

    const result = await scanDiff({
      diff: SQLI_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITHOUT_KEY,
      ...io,
    });

    expect(result.engine).toBe('local');
    expect(out()).toContain('local engine');
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.exitCode).toBe(EXIT.BLOCKED);
  });

  it('does not call a provider even when one is supplied', async () => {
    // `--local` is a promise that nothing leaves the machine, so it has to hold
    // even when credentials exist. Otherwise a developer reaching for the safe
    // option during an incident would silently transmit anyway.
    const { io, out } = capture();
    const client = stubClient({ triage: TRIAGE_HIT });

    const result = await scanDiff({
      diff: SQLI_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      local: true,
      client,
      ...io,
    });

    expect(result.engine).toBe('local');
    expect(out()).toContain('local engine');
  });
});

describe('scanDiff — Remote Mode', () => {
  it('uses the AI engine when a key is present', async () => {
    const { io, out } = capture();

    const result = await scanDiff({
      diff: CLEAN_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      client: stubClient({ triage: TRIAGE_HIT }),
      ...io,
    });

    expect(result.engine).toBe('remote');
    expect(out()).toContain('remote AI engine');
    // A finding the regex rules cannot reach at all — the reason Remote Mode
    // exists on top of Phase 2 rather than instead of it.
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe('logic_bug');
    expect(result.exitCode).toBe(EXIT.BLOCKED);
  });

  it('shows the suggested patch but states that nothing was applied', async () => {
    const { io, out } = capture();

    await scanDiff({
      diff: CLEAN_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      client: stubClient({ triage: TRIAGE_HIT }),
      ...io,
    });

    const report = out();
    expect(report).toContain('confidence: high');
    expect(report).toContain('const sub = (a, b) => a - b;');
    // Phase 5 applies patches. Until then the report must not imply it already
    // did — a developer who believes a fix is in place will not make it.
    expect(report).toContain('nothing is changed yet');
  });

  it('reports findings deep analysis cleared, without counting them', async () => {
    const { io, out } = capture();
    const cleared = JSON.stringify({
      file: 'src/math.js',
      line_range: [2, 2],
      severity: 'Low',
      category: 'logic_bug',
      explanation: 'The subtraction is intentional.',
      suggested_patch: '',
      confidence: 'high',
    });

    const result = await scanDiff({
      diff: CLEAN_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      client: stubClient({ triage: TRIAGE_HIT, patch: cleared }),
      ...io,
    });

    expect(result.findings).toHaveLength(0);
    expect(result.dismissed).toHaveLength(1);
    expect(result.exitCode).toBe(EXIT.OK);
    expect(out()).toContain('Cleared as false positives');
    expect(out()).toContain('no issues found');
  });

  it('puts operational notes on stderr, keeping stdout report-only', async () => {
    // The channel split matters more in Remote Mode than anywhere else, because
    // "we redacted two values and skipped three files" is exactly the sort of
    // line that would corrupt a report someone is parsing.
    const { io, out, err } = capture();

    await scanDiff({
      diff: SECRET_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      client: stubClient({ triage: '{"findings":[]}' }),
      ...io,
    });

    expect(err()).toContain('Redacted');
    expect(out()).toContain('no issues found');
    expect(out()).not.toContain('Redacted');
  });
});

describe('scanDiff — the fallback (PRD §6.3)', () => {
  it('falls back to Local Mode, loudly, when the provider is unreachable', async () => {
    // The Phase 4 acceptance criterion. A network failure must not crash the
    // hook and must not produce an empty report that reads as a clean scan.
    const { io, out, err } = capture();

    const result = await scanDiff({
      diff: SQLI_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      client: stubClient({ triage: new LlmError('could not reach https://api.deepseek.com') }),
      ...io,
    });

    expect(result.engine).toBe('local');
    expect(result.exitCode).toBe(EXIT.BLOCKED);
    // The local engine found the SQL injection, so the commit is still gated.
    expect(result.findings.length).toBeGreaterThan(0);
    expect(out()).toContain('local engine');

    const warnings = err();
    expect(warnings).toContain('Remote AI Mode failed');
    expect(warnings).toContain('DID NOT RUN');
    // The distinction that matters: the developer must not read this as "the AI
    // looked and found nothing".
    expect(warnings).toContain('does not mean the AI pass found nothing');
    expect(warnings).toContain('could not reach');
  });

  it('does not leak the API key into the fallback warning', async () => {
    // The provider is the one component that knows the key, and its error
    // message is the one string from it that reaches the terminal. FR-10.
    const { io, err } = capture();

    await scanDiff({
      diff: SQLI_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      client: stubClient({ triage: new LlmError(`provider echoed back Bearer ${KEY}`) }),
      ...io,
    });

    // The stub deliberately bypasses the client's own redaction, so this
    // asserts the hook redacts independently. Two guards, because a key in a
    // CI log cannot be taken back.
    expect(err()).not.toContain(KEY);
    expect(err()).toContain('Remote AI Mode failed');
  });

  it('makes --remote without a key an error, not a quiet local scan', async () => {
    // Not a fallback, deliberately: the flag asked for an AI scan, and handing
    // back a regex scan would misrepresent what ran.
    const { io, out, err } = capture();

    const result = await scanDiff({
      diff: SQLI_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITHOUT_KEY,
      remote: true,
      ...io,
    });

    expect(result.exitCode).toBe(EXIT.ERROR);
    expect(result.engine).toBe('local');
    expect(result.findings).toHaveLength(0);
    expect(out()).not.toContain('local engine');
    expect(err()).toContain(API_KEY_VAR);
    expect(err()).toContain('--remote');
  });

  it('rejects --local and --remote together', async () => {
    const { io, err } = capture();

    const result = await scanDiff({
      diff: SQLI_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITHOUT_KEY,
      local: true,
      remote: true,
      ...io,
    });

    expect(result.exitCode).toBe(EXIT.ERROR);
    expect(err()).toContain('cannot be combined');
  });

  it('keeps a clean remote scan clean, and exits zero', async () => {
    // The other half of the fallback story: a remote scan that genuinely finds
    // nothing must exit zero rather than being treated as a failure to retry.
    const { io } = capture();

    const result = await scanDiff({
      diff: CLEAN_DIFF,
      repoRoot: REPO_ROOT,
      environment: WITH_KEY,
      client: stubClient({ triage: '{"findings":[]}' }),
      ...io,
    });

    expect(result.engine).toBe('remote');
    expect(result.findings).toHaveLength(0);
    expect(result.exitCode).toBe(EXIT.OK);
  });
});
