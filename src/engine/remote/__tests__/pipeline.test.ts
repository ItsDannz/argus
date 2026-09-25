/**
 * The two-stage pipeline, end to end, against a stub provider.
 *
 * This is the file that matters most in Phase 4. The prompt wording is checked
 * against the live API (Phase 6), the HTTP shape is checked by asserting on
 * `buildRequestBody`, but the ROUTING — which answer wins, what counts towards
 * the threshold, what gets reported without a patch, and what never leaves the
 * machine — is pure logic that has to hold every single time. A regression here
 * does not look like a crash; it looks like a scan that reported six findings
 * instead of seven.
 *
 * The stub replaces only the network hop, so everything between "here is a diff"
 * and "here is what the developer sees" is the real code path.
 */

import { describe, expect, it } from '@jest/globals';

import type { Finding } from '../../findings';
import type {
  LlmClient,
  LlmRequest,
} from '../client';
import { LlmError } from '../client';
import { runRemoteScan } from '../index';

/** A rule-engine finding, shaped exactly as the Local Engine emits them. */
function secretFinding(file: string, line: number): Finding {
  return {
    file,
    line,
    category: 'hardcoded_secret',
    ruleId: 'hardcoded-secret-assignment',
    severity: 'High',
    message: 'Possible hardcoded credential.',
  };
}

// ---------------------------------------------------------------------------
// A stub provider
// ---------------------------------------------------------------------------

/** Records every request it is given, so the tests can assert on what was sent. */
interface Stub extends LlmClient {
  readonly requests: LlmRequest[];
  /** The user prompt of the request whose system prompt contained `marker`. */
  promptFor(marker: string): string | undefined;
}

/** The file a Stage-2 request was about, read back out of the prompt. */
function fileAsked(request: LlmRequest): string {
  return /^File: (.+)$/m.exec(request.user)?.[1] ?? 'unknown';
}

/**
 * What a stub answer may be: raw text (to test malformed output), an Error (to
 * test a failure), or an object that gets JSON-encoded for readability.
 */
type Answer = string | Error | Record<string, unknown>;

/**
 * Builds a client that answers triage and deep analysis from canned text.
 *
 * The two stages are told apart by their system prompt, which is exactly how the
 * real pipeline distinguishes them — there is no request id or ordering trick,
 * so the stub cannot accidentally pass while the real routing is broken.
 *
 * The default Stage-2 answer echoes back the file it was ASKED about, taken from
 * the prompt. A stub that always named one hard-coded file would exercise the
 * pipeline's cross-file guard on every test and assert on misattributed results,
 * which is a property of the stub rather than of the code under test.
 */
function stubProvider(answers: {
  triage?: Answer;
  patch?: (hunkIndex: number, request: LlmRequest) => Answer;
}): Stub {
  const requests: LlmRequest[] = [];
  let patchCalls = 0;

  return {
    model: 'stub-model',
    requests,

    promptFor(marker: string): string | undefined {
      return requests.find((request) => request.system.includes(marker))?.user;
    },

    async complete(request: LlmRequest): Promise<string> {
      requests.push(request);

      if (request.system.includes('triage engine')) {
        const answer = answers.triage ?? '{"findings":[]}';
        if (answer instanceof Error) throw answer;
        // Triage answers are always raw text: the interesting cases are a
        // well-formed array, a fenced one, and something that is not JSON.
        return asText(answer);
      }

      const file = fileAsked(request);
      const answer = answers.patch?.(patchCalls, request) ?? {
        file,
        line_range: [2, 2],
        severity: file === 'src/db.js' ? 'Critical' : 'High',
        category: file === 'src/db.js' ? 'sql_injection' : 'command_injection',
        explanation: `The change in ${file} is still exploitable.`,
        suggested_patch: `--- a/${file}\n+++ b/${file}\n@@ -1 +1 @@\n`,
        confidence: 'high',
      };
      patchCalls += 1;
      if (answer instanceof Error) throw answer;
      return typeof answer === 'string' ? answer : JSON.stringify(answer);
    },
  };
}

/** Narrows a stub answer to text, failing the test rather than the pipeline. */
function asText(answer: Answer | undefined): string {
  if (typeof answer !== 'string') throw new Error('the stub was configured with a non-text answer');
  return answer;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Two hunks in two files, both genuinely worth flagging. */
const TWO_FILE_DIFF = [
  'diff --git a/src/db.js b/src/db.js',
  'new file mode 100644',
  'index 0000000..1111111',
  '--- /dev/null',
  '+++ b/src/db.js',
  '@@ -0,0 +1,3 @@',
  '+function findUser(db, name) {',
  "+  return db.query(\"SELECT * FROM users WHERE name = '\" + name + \"'\");",
  '+}',
  'diff --git a/src/run.js b/src/run.js',
  'new file mode 100644',
  'index 0000000..2222222',
  '--- /dev/null',
  '+++ b/src/run.js',
  '@@ -0,0 +1,2 @@',
  '+const { execSync } = require("child_process");',
  '+execSync("convert " + process.argv[2]);',
  '',
].join('\n');

const TRIAGE_TWO = JSON.stringify({
  findings: [
    {
      file: 'src/db.js',
      line_range: [2, 2],
      severity: 'Critical',
      category: 'sql_injection',
      summary: 'Request data concatenated into a SQL query.',
    },
    {
      file: 'src/run.js',
      line_range: [2, 2],
      severity: 'High',
      category: 'command_injection',
      summary: 'An argv value is passed to a shell command.',
    },
  ],
});

const CREDENTIALS = { apiKey: 'sk-test-key', model: 'stub-model' };
const REMOTE = { maxDeepAnalysisHunks: 5, timeoutMs: 5_000 };

/** Every note, joined, for tests that only care whether something was said. */
const notesText = (notes: readonly string[]): string => notes.join('\n');

// ---------------------------------------------------------------------------

describe('runRemoteScan — the happy path', () => {
  it('turns a triage hit plus a deep answer into one counted finding', async () => {
    const client = stubProvider({ triage: TRIAGE_TWO });

    const outcome = await runRemoteScan({
      diff: TWO_FILE_DIFF,
      credentials: CREDENTIALS,
      remote: REMOTE,
      client,
    });

    expect(outcome.findings).toHaveLength(2);
    expect(outcome.findings.map((finding) => finding.severity)).toEqual(['Critical', 'High']);
    expect(outcome.findings[0]).toMatchObject({
      file: 'src/db.js',
      line: 2,
      ruleId: 'sql_injection',
    });
    expect(outcome.analyses).toHaveLength(2);
    expect(outcome.analyses[0]?.patch).not.toBe('');
    // One triage request plus one deep-analysis request per flagged hunk.
    expect(outcome.requestCount).toBe(3);
  });

  it('asks Stage 1 for no reasoning and Stage 2 for reasoning', async () => {
    // The whole cost design in one assertion. If Stage 1 is ever sent with
    // thinking on, nothing fails — the scan just costs more than it should, in a
    // way that only shows up on a bill. So it is asserted, not assumed.
    const client = stubProvider({ triage: TRIAGE_TWO });

    await runRemoteScan({ diff: TWO_FILE_DIFF, credentials: CREDENTIALS, remote: REMOTE, client });

    const triage = client.requests.filter((request) => request.system.includes('triage engine'));
    const deep = client.requests.filter((request) => !request.system.includes('triage engine'));

    expect(triage).toHaveLength(1);
    expect(triage[0]?.reasoning).toBe(false);
    expect(deep).toHaveLength(2);
    expect(deep.every((request) => request.reasoning)).toBe(true);
  });

  it('sends the flagged hunk to Stage 2, not the whole diff', async () => {
    const client = stubProvider({ triage: TRIAGE_TWO });

    await runRemoteScan({ diff: TWO_FILE_DIFF, credentials: CREDENTIALS, remote: REMOTE, client });

    const deep = client.promptFor('deep-analysis and patching engine');
    expect(deep).toContain('File: src/db.js');
    expect(deep).toContain('SELECT * FROM users');
    // The other file was a separate hunk and must not be in this request.
    expect(deep).not.toContain('execSync');
  });
});

describe('runRemoteScan — failure handling', () => {
  it('propagates a Stage-1 failure so the caller can fall back to Local', async () => {
    // Stage 1 failing is the documented fallback trigger (PRD §6.3). Swallowing
    // it here would present an empty, successful-looking scan instead.
    const client = stubProvider({ triage: new LlmError('could not reach the provider') });

    await expect(
      runRemoteScan({ diff: TWO_FILE_DIFF, credentials: CREDENTIALS, remote: REMOTE, client }),
    ).rejects.toThrow(LlmError);
  });

  it('keeps triage findings when Stage 2 fails, without throwing', async () => {
    const client = stubProvider({
      triage: TRIAGE_TWO,
      patch: () => new LlmError('provider returned 503', 'http', 503),
    });

    const outcome = await runRemoteScan({
      diff: TWO_FILE_DIFF,
      credentials: CREDENTIALS,
      remote: REMOTE,
      client,
    });

    // A partial outage must not become a green scan.
    expect(outcome.findings).toHaveLength(2);
    expect(outcome.analyses).toHaveLength(0);
    expect(outcome.notAnalysed).toHaveLength(2);
    expect(notesText(outcome.notes)).toContain('Deep analysis stopped');
  });

  it('stops calling the provider after the first Stage-2 failure', async () => {
    // A failed call is likely to be followed by more failed calls. Retrying the
    // rest would spend the cap on timeouts and turn one hiccup into a stall.
    //
    // The kind is load-bearing here and is why it is spelled out: `http` is an
    // ANSWER — the provider understood the request and refused it — so one call
    // is right. `empty` is the one kind that gets a retry, and this test fails
    // if that ever widens (see the retry tests below).
    const client = stubProvider({
      triage: TRIAGE_TWO,
      patch: () => new LlmError('provider returned 503', 'http', 503),
    });

    await runRemoteScan({ diff: TWO_FILE_DIFF, credentials: CREDENTIALS, remote: REMOTE, client });

    const deep = client.requests.filter((request) => !request.system.includes('triage engine'));
    expect(deep).toHaveLength(1);
  });

  it('keeps Stage-2 results already obtained when a later hunk fails', async () => {
    const client = stubProvider({
      triage: TRIAGE_TWO,
      patch: (index) => {
        if (index === 0) {
          return {
            file: 'src/db.js',
            line_range: [2, 2],
            severity: 'Critical',
            category: 'sql_injection',
            explanation: 'Parameterise the query.',
            suggested_patch: '--- a/src/db.js\n+++ b/src/db.js\n',
            confidence: 'high',
          };
        }
        return new LlmError('provider returned 503', 'http', 503);
      },
    });

    const outcome = await runRemoteScan({
      diff: TWO_FILE_DIFF,
      credentials: CREDENTIALS,
      remote: REMOTE,
      client,
    });

    expect(outcome.analyses).toHaveLength(1);
    expect(outcome.analyses[0]?.patch).not.toBe('');
    // Both findings survive: one carrying a patch, one reported from triage.
    expect(outcome.findings).toHaveLength(2);
    expect(outcome.notAnalysed).toHaveLength(1);
    expect(outcome.notAnalysed[0]?.file).toBe('src/run.js');
  });

  it('treats one hunk’s unparseable answer as that hunk’s problem only', async () => {
    const client = stubProvider({
      triage: TRIAGE_TWO,
      patch: (index) => (index === 0 ? 'I could not comply with that request.' : '{"file":"src/run.js","line_range":[2,2],"severity":"High","category":"command_injection","explanation":"Shell injection.","suggested_patch":"--- a\\n+++ b\\n","confidence":"medium"}'),
    });

    const outcome = await runRemoteScan({
      diff: TWO_FILE_DIFF,
      credentials: CREDENTIALS,
      remote: REMOTE,
      client,
    });

    // The bad hunk is reported without a patch; the good one still gets analysed.
    expect(outcome.analyses).toHaveLength(1);
    expect(outcome.analyses[0]?.file).toBe('src/run.js');
    expect(outcome.notAnalysed).toHaveLength(1);
    expect(notesText(outcome.notes)).toContain('src/db.js returned something unusable');
  });
});

describe('runRemoteScan — the empty-answer retry', () => {
  /**
   * The one Stage-2 failure that is not an answer to the request.
   *
   * Observed live: the provider returned a well-formed envelope with no message
   * content for a hunk, having answered the same call successfully moments
   * earlier. That is a hiccup rather than a structural incompatibility, and
   * Phase 5's whole value is the patch, so the pipeline spends one more request
   * before giving up on it. Every other kind — transport, http, malformed — is
   * an answer, and asking again gets the same one.
   */
  const EMPTY = new LlmError(
    'provider returned nothing usable — the response contained no message content',
    'empty',
  );

  /** Mirrors the stub's own default answer, for the attempts after the first. */
  function answerFor(request: LlmRequest): Record<string, unknown> {
    const file = fileAsked(request);
    return {
      file,
      line_range: [2, 2],
      severity: file === 'src/db.js' ? 'Critical' : 'High',
      category: file === 'src/db.js' ? 'sql_injection' : 'command_injection',
      explanation: `The change in ${file} is still exploitable.`,
      suggested_patch: `--- a/${file}\n+++ b/${file}\n@@ -1 +1 @@\n`,
      confidence: 'high',
    };
  }

  it('retries once and keeps the patch when the second attempt answers', async () => {
    const client = stubProvider({
      triage: TRIAGE_TWO,
      patch: (index, request) => (index === 0 ? EMPTY : answerFor(request)),
    });
    const said: string[] = [];

    const outcome = await runRemoteScan({
      diff: TWO_FILE_DIFF,
      credentials: CREDENTIALS,
      remote: REMOTE,
      client,
      onProgress: (message) => void said.push(message),
    });

    // Both hunks analysed, both with patches — the retry recovered the first.
    expect(outcome.analyses).toHaveLength(2);
    expect(outcome.analyses.every((analysis) => analysis.patch !== '')).toBe(true);
    expect(outcome.notAnalysed).toHaveLength(0);
    expect(outcome.findings).toHaveLength(2);

    // One triage call, then two for the first hunk (empty, then answered) and
    // one for the second. The cap counts requests, not hunks, so a silently
    // unlimited retry would show up here rather than as a hung commit.
    expect(outcome.requestCount).toBe(4);

    // The retry is not silent. A scan that took an extra round trip and said
    // nothing would look identical to one that did not need it.
    expect(notesText(said)).toContain('came back empty; retrying it once');
    expect(notesText(outcome.notes)).not.toContain('Deep analysis stopped');
  });

  it('gives up after exactly one retry rather than hammering the provider', async () => {
    // Two identical empty answers in a row is a pattern, not a hiccup. The
    // caller already knows what to do with it: keep what was gathered and report
    // the rest without patches.
    const client = stubProvider({
      triage: TRIAGE_TWO,
      patch: () => EMPTY,
    });

    const outcome = await runRemoteScan({
      diff: TWO_FILE_DIFF,
      credentials: CREDENTIALS,
      remote: REMOTE,
      client,
    });

    const deep = client.requests.filter((request) => !request.system.includes('triage engine'));
    // Two, not three: the retry, and then no more.
    expect(deep).toHaveLength(2);
    expect(outcome.requestCount).toBe(3);

    // Degrades to the triage-only path — the pre-existing behaviour, reached one
    // request later. A partial outage must not become a green scan.
    expect(outcome.analyses).toHaveLength(0);
    expect(outcome.findings).toHaveLength(2);
    expect(outcome.notAnalysed).toHaveLength(2);
    expect(notesText(outcome.notes)).toContain('Deep analysis stopped');
    // The failure reported is the retry's, and it still says why.
    expect(notesText(outcome.notes)).toContain('nothing usable');
  });

  it('does not retry an answer that failed for any other reason', async () => {
    // The narrowness is the whole design. A 503 is an answer about the request,
    // a transport error is an answer about the network, and malformed text is an
    // answer about the model — repeating any of them costs a round trip and
    // returns the same thing.
    for (const failure of [
      new LlmError('provider returned 503', 'http', 503),
      new LlmError('could not reach https://api.deepseek.com'),
      new LlmError('provider returned a non-JSON body', 'malformed'),
    ]) {
      const client = stubProvider({ triage: TRIAGE_TWO, patch: () => failure });

      await runRemoteScan({
        diff: TWO_FILE_DIFF,
        credentials: CREDENTIALS,
        remote: REMOTE,
        client,
      });

      const deep = client.requests.filter((request) => !request.system.includes('triage engine'));
      expect(deep).toHaveLength(1);
    }
  });
});

describe('runRemoteScan — false positives', () => {
  it('drops a finding that deep analysis refuses to patch, and says so', async () => {
    // The reason Stage 2 exists. Triage over-reports by design; a finding that
    // survives triage but not deep analysis must not reach the threshold, or the
    // developer is blocked by a false alarm they cannot act on.
    const client = stubProvider({
      triage: TRIAGE_TWO,
      // The first hunk (db.js, worst first) is cleared; the second still gets a
      // patch, so the test shows a dismissal and a confirmation side by side.
      patch: (index, request) => ({
        file: fileAsked(request),
        line_range: [2, 2] as [number, number],
        severity: index === 0 ? 'Low' : 'High',
        category: index === 0 ? 'sql_injection' : 'command_injection',
        explanation:
          index === 0
            ? 'The value is a hard-coded literal, not request data.'
            : 'An argv value reaches the shell.',
        suggested_patch: index === 0 ? '' : '--- a/x\n+++ b/x\n@@ -1 +1 @@\n',
        confidence: 'high' as const,
      }),
    });

    const outcome = await runRemoteScan({
      diff: TWO_FILE_DIFF,
      credentials: CREDENTIALS,
      remote: REMOTE,
      client,
    });

    const cleared = outcome.findings.filter((finding) => finding.file === 'src/db.js');
    // db.js is exempt: deep analysis cleared it. run.js still stands.
    expect(cleared).toHaveLength(0);
    expect(outcome.dismissed).toHaveLength(1);
    expect(outcome.dismissed[0]?.file).toBe('src/db.js');
    expect(outcome.dismissed[0]?.message).toContain('hard-coded literal');
    // Reported, but never counted — the distinction the renderer draws on.
    expect(outcome.findings.map((finding) => finding.file)).toEqual(['src/run.js']);
    expect(notesText(outcome.notes)).toContain('cleared 1 triage finding');
  });
});

describe('runRemoteScan — the hunk cap', () => {
  it('deep-analyses only the worst hunks and reports the rest unpatched', async () => {
    const client = stubProvider({ triage: TRIAGE_TWO });

    const outcome = await runRemoteScan({
      diff: TWO_FILE_DIFF,
      credentials: CREDENTIALS,
      remote: { ...REMOTE, maxDeepAnalysisHunks: 1 },
      client,
    });

    // Critical (db.js) wins the single slot; High (run.js) falls outside.
    expect(outcome.analyses).toHaveLength(1);
    expect(outcome.analyses[0]?.file).toBe('src/db.js');
    // The unanalysed hunk is NOT dropped — it is reported without a patch, and
    // it still counts, because a finding nobody refuted is still a finding.
    expect(outcome.findings).toHaveLength(2);
    expect(outcome.notAnalysed).toHaveLength(1);
    expect(outcome.notAnalysed[0]?.file).toBe('src/run.js');

    const notes = notesText(outcome.notes);
    expect(notes).toContain('limit of 1 deep-analysis hunk');
    // The report must name what was skipped. A truncated scan that looks
    // complete is the failure this cap has to avoid.
    expect(notes).toContain('src/run.js');
  });

  it('makes no Stage-2 calls at all when the cap is zero', async () => {
    const client = stubProvider({ triage: TRIAGE_TWO });

    const outcome = await runRemoteScan({
      diff: TWO_FILE_DIFF,
      credentials: CREDENTIALS,
      remote: { ...REMOTE, maxDeepAnalysisHunks: 0 },
      client,
    });

    expect(outcome.analyses).toHaveLength(0);
    expect(outcome.findings).toHaveLength(2);
    expect(outcome.requestCount).toBe(1);
  });
});

describe('runRemoteScan — what leaves the machine', () => {
  it('never transmits an excluded file', async () => {
    const client = stubProvider({ triage: TRIAGE_TWO });

    const outcome = await runRemoteScan({
      diff: TWO_FILE_DIFF,
      credentials: CREDENTIALS,
      remote: REMOTE,
      client,
      exclude: (filePath) => filePath === 'src/run.js',
    });

    for (const request of client.requests) {
      expect(request.user).not.toContain('execSync');
    }
    // Excluding a file is not the same as pretending it does not exist: the note
    // has to say it went unexamined.
    expect(notesText(outcome.notes)).toContain('src/run.js');
    expect(notesText(outcome.notes)).toContain('Excluded by configuration');
  });

  it('redacts a secret before it reaches the provider', async () => {
    const diff = [
      'diff --git a/src/config.js b/src/config.js',
      'new file mode 100644',
      'index 0000000..3333333',
      '--- /dev/null',
      '+++ b/src/config.js',
      '@@ -0,0 +1,1 @@',
      '+const API_KEY = "sk-live-9f2b7c41d8e35a60b4c7f1e2";',
      '',
    ].join('\n');

    const client = stubProvider({ triage: '{"findings":[]}' });

    const outcome = await runRemoteScan({
      diff,
      credentials: CREDENTIALS,
      remote: REMOTE,
      client,
    });

    // The guarantee is about the wire, so it is asserted against the wire.
    expect(client.requests[0]?.user).not.toContain('sk-live-9f2b7c41d8e35a60b4c7f1e2');
    expect(client.requests[0]?.user).toContain('REDACTED');
    expect(outcome.redactions.length).toBeGreaterThan(0);
    expect(notesText(outcome.notes)).toContain('Redacted');
  });

  it('withholds a secret the heuristics miss, because the rules reported it', async () => {
    const diff = [
      'diff --git a/src/config.js b/src/config.js',
      'new file mode 100644',
      'index 0000000..4444444',
      '--- /dev/null',
      '+++ b/src/config.js',
      '@@ -0,0 +1,2 @@',
      '+const config = {',
      '+  dbPassword: "Spr1ng2024!prod",',
      '',
    ].join('\n');

    const client = stubProvider({ triage: '{"findings":[]}' });
    await runRemoteScan({ diff, credentials: CREDENTIALS, remote: REMOTE, client });

    // The premise, and the reason this test exists: on its own, the redactor
    // walks straight past this value. The rule engine's pattern matches
    // `dbPassword` (the credential name is a substring of the identifier, and
    // the rule needs no word boundary) while every heuristic in redact.ts needs
    // one, and 15 characters is under the entropy backstop's floor.
    expect(client.requests[0]?.user).toContain('Spr1ng2024!prod');

    const reported = stubProvider({ triage: '{"findings":[]}' });
    const outcome = await runRemoteScan({
      diff,
      credentials: CREDENTIALS,
      remote: REMOTE,
      client: reported,
      baseline: [secretFinding('src/config.js', 2)],
    });

    expect(reported.requests[0]?.user).not.toContain('Spr1ng2024!prod');
    expect(reported.requests[0]?.user).toContain('«REDACTED:known-secret»');
    expect(outcome.redactions).toContainEqual({ file: 'src/config.js', label: 'known-secret' });
  });

  it('still sends the vulnerability it was asked to reason about', async () => {
    const diff = [
      'diff --git a/src/users.js b/src/users.js',
      'new file mode 100644',
      'index 0000000..5555555',
      '--- /dev/null',
      '+++ b/src/users.js',
      '@@ -0,0 +1,1 @@',
      `+const sql = "SELECT id FROM users WHERE name = \'" + name + "\'";`,
      '',
    ].join('\n');

    const client = stubProvider({ triage: '{"findings":[]}' });
    await runRemoteScan({
      diff,
      credentials: CREDENTIALS,
      remote: REMOTE,
      client,
      // A rule-engine finding in a category that is not a credential. Only
      // `hardcoded_secret` crosses into the redactor: withholding the injection
      // would remove the thing the model was asked to fix.
      baseline: [
        {
          file: 'src/users.js',
          line: 1,
          category: 'sql_injection',
          ruleId: 'sql-string-concatenation',
          severity: 'Critical',
          message: 'SQL assembled with string concatenation.',
        },
      ],
    });

    expect(client.requests[0]?.user).toContain('SELECT id FROM users WHERE name =');
    expect(client.requests[0]?.user).not.toContain('REDACTED');
  });

  it('sends a secret no rule and no pattern recognises — the residual', async () => {
    const diff = [
      'diff --git a/src/db.js b/src/db.js',
      'new file mode 100644',
      'index 0000000..6666666',
      '--- /dev/null',
      '+++ b/src/db.js',
      '@@ -0,0 +1,1 @@',
      '+const DATABASE_URL = "pg-super-secret-99";',
      '',
    ].join('\n');

    const client = stubProvider({ triage: '{"findings":[]}' });
    const outcome = await runRemoteScan({ diff, credentials: CREDENTIALS, remote: REMOTE, client });

    // Pinned so the boundary stays visible rather than being rediscovered as a
    // surprise. Nothing credential-shaped precedes the `=`, so no rule reports
    // the line and nothing reaches the redactor through the baseline; the value
    // is 18 characters, under the entropy backstop's 20. What is left is
    // structural — redaction is pattern matching — and the answer is not a lower
    // floor, which would start eating lockfile hashes, but the developer not
    // committing the value.
    expect(outcome.redactions).toEqual([]);
    expect(client.requests[0]?.user).toContain('pg-super-secret-99');
  });

  it('never sends the API key in a prompt', async () => {
    const client = stubProvider({ triage: TRIAGE_TWO });

    await runRemoteScan({ diff: TWO_FILE_DIFF, credentials: CREDENTIALS, remote: REMOTE, client });

    for (const request of client.requests) {
      expect(request.system).not.toContain(CREDENTIALS.apiKey);
      expect(request.user).not.toContain(CREDENTIALS.apiKey);
    }
  });

  it('withholds a patch that quotes a redacted value rather than writing a placeholder into a file', async () => {
    // The hazard is concrete: a Stage-2 patch can legitimately quote the line it
    // is fixing. When that line carries a redaction placeholder, applying the
    // patch would put `«REDACTED:...»` into the developer's source. The patch is
    // withheld; the explanation and severity survive.
    const diff = [
      'diff --git a/src/config.js b/src/config.js',
      'new file mode 100644',
      'index 0000000..3333333',
      '--- /dev/null',
      '+++ b/src/config.js',
      '@@ -0,0 +1,1 @@',
      '+const API_KEY = "sk-live-9f2b7c41d8e35a60b4c7f1e2";',
      '',
    ].join('\n');

    const client = stubProvider({
      triage: JSON.stringify({
        findings: [
          {
            file: 'src/config.js',
            line_range: [1, 1],
            severity: 'Critical',
            category: 'hardcoded_secret',
            summary: 'A live API key is committed.',
          },
        ],
      }),
      patch: (index, request) => {
        // Echo the redacted line back inside the patch, which is exactly what
        // the model would do if it quoted the code it was shown.
        const quoted = /\+const API_KEY.*/.exec(request.user)?.[0] ?? '+const API_KEY = ???';
        return {
          file: 'src/config.js',
          line_range: [1, 1],
          severity: 'Critical',
          category: 'hardcoded_secret',
          explanation: 'Move this into the environment.',
          suggested_patch: `--- a/src/config.js\n+++ b/src/config.js\n@@ -1 +1 @@\n-${quoted.slice(1)}\n+const API_KEY = process.env.API_KEY;\n`,
          confidence: 'high',
        };
      },
    });

    const outcome = await runRemoteScan({
      diff,
      credentials: CREDENTIALS,
      remote: REMOTE,
      client,
    });

    expect(outcome.analyses).toHaveLength(1);
    expect(outcome.analyses[0]?.patch).toBe('');
    expect(outcome.analyses[0]?.withheld).toContain('redacted');
    // Still a finding, so the developer still has to deal with it.
    expect(outcome.findings).toHaveLength(1);
    expect(outcome.findings[0]?.severity).toBe('Critical');
  });
});

describe('runRemoteScan — untrusted model output', () => {
  it('discards a finding for a file that was never in the diff', async () => {
    const client = stubProvider({
      triage: JSON.stringify({
        findings: [
          {
            file: 'src/does-not-exist.js',
            line_range: [1, 1],
            severity: 'Critical',
            category: 'sql_injection',
            summary: 'Hallucinated.',
          },
        ],
      }),
    });

    const outcome = await runRemoteScan({
      diff: TWO_FILE_DIFF,
      credentials: CREDENTIALS,
      remote: REMOTE,
      client,
    });

    expect(outcome.findings).toHaveLength(0);
    expect(notesText(outcome.notes)).toContain('not in the diff');
  });

  it('still reports a finding that matched no hunk, without a patch', async () => {
    // The path is real, the line number is not. There is nothing to deep-analyse
    // and no patch can be produced — but a finding the scan genuinely made must
    // not vanish, so it counts and is listed as unpatched.
    const client = stubProvider({
      triage: JSON.stringify({
        findings: [
          {
            file: 'src/db.js',
            line_range: [9000, 9000],
            severity: 'High',
            category: 'sql_injection',
            summary: 'Off the end of the hunk.',
          },
        ],
      }),
    });

    const outcome = await runRemoteScan({
      diff: TWO_FILE_DIFF,
      credentials: CREDENTIALS,
      remote: REMOTE,
      client,
    });

    // The nearest-hunk fallback still finds a hunk to analyse, so this lands as
    // a normal analysis rather than as `unmatched`. Either way it must survive.
    expect(outcome.findings).toHaveLength(1);
    expect(
      outcome.analyses.length + outcome.notAnalysed.length,
    ).toBeGreaterThanOrEqual(1);
  });

  it('rejects a triage entry whose severity is unusable', async () => {
    // Severity is the threshold's only input. An invented value must not be
    // guessed at, because either guess can silently mis-gate a commit.
    const client = stubProvider({
      triage: JSON.stringify({
        findings: [
          {
            file: 'src/db.js',
            line_range: [2, 2],
            severity: 'Very Bad',
            category: 'sql_injection',
            summary: 'Bad severity.',
          },
        ],
      }),
    });

    const outcome = await runRemoteScan({
      diff: TWO_FILE_DIFF,
      credentials: CREDENTIALS,
      remote: REMOTE,
      client,
    });

    expect(outcome.findings).toHaveLength(0);
    expect(notesText(outcome.notes)).toContain('unusable severity');
  });

  it('keeps a finding whose category is unknown but whose severity is fine', async () => {
    // The asymmetric rule: category is a label, severity is a decision input.
    // The cap is zeroed so the Stage-1 finding is what gets counted — otherwise
    // Stage 2 supplies the category and the coercion this asserts never runs.
    const client = stubProvider({
      triage: JSON.stringify({
        findings: [
          {
            file: 'src/db.js',
            line_range: [2, 2],
            severity: 'High',
            category: 'quantum_flux',
            summary: 'Unknown taxonomy.',
          },
        ],
      }),
    });

    const outcome = await runRemoteScan({
      diff: TWO_FILE_DIFF,
      credentials: CREDENTIALS,
      remote: { ...REMOTE, maxDeepAnalysisHunks: 0 },
      client,
    });

    expect(outcome.findings).toHaveLength(1);
    expect(outcome.findings[0]?.ruleId).toBe('other');
  });

  it('rejects a Stage-2 answer about a different file than the one asked about', async () => {
    // Cross-file drift. The named file IS in the diff, so nothing else catches
    // it — and if it were accepted, a run.js finding would be silently rewritten
    // as a db.js one and handed a patch for code the model was never shown.
    const client = stubProvider({
      triage: TRIAGE_TWO,
      patch: (index) => ({
        file: 'src/run.js',
        line_range: [2, 2] as [number, number],
        severity: 'Medium',
        category: 'other',
        explanation: 'Wrong file entirely.',
        suggested_patch: '--- a/x\n+++ b/x\n@@ -1 +1 @@\n',
        confidence: 'high' as const,
      }),
    });

    const outcome = await runRemoteScan({
      diff: TWO_FILE_DIFF,
      credentials: CREDENTIALS,
      remote: REMOTE,
      client,
      // The db.js hunk is asked about first, and answered about run.js.
    });

    // The db.js finding survives from triage, with no patch. It is not
    // rewritten into a second run.js finding.
    const db = outcome.findings.filter((finding) => finding.file === 'src/db.js');
    expect(db).toHaveLength(1);
    expect(db[0]?.severity).toBe('Critical');
    expect(notesText(outcome.notes)).toContain('answered about src/run.js instead');
  });

  it('survives a triage response that is not JSON at all', async () => {
    const client = stubProvider({ triage: 'Sure! Here are the issues I found:' });

    await expect(
      runRemoteScan({ diff: TWO_FILE_DIFF, credentials: CREDENTIALS, remote: REMOTE, client }),
    ).rejects.toThrow(/not valid JSON/);
  });

  it('reports nothing, without calling the provider, when the diff is empty', async () => {
    const client = stubProvider({ triage: TRIAGE_TWO });

    const outcome = await runRemoteScan({
      diff: '',
      credentials: CREDENTIALS,
      remote: REMOTE,
      client,
    });

    expect(outcome.findings).toHaveLength(0);
    expect(outcome.requestCount).toBe(0);
    expect(client.requests).toHaveLength(0);
  });
});

describe('runRemoteScan — deadline', () => {
  it('gives the provider a signal that is already aborted when the caller is', async () => {
    // The signal the pipeline hands down is `AbortSignal.any([caller, timeout])`.
    // If the caller's signal is dropped, cancelling a scan does nothing: the
    // requests keep going and the process cannot exit cleanly.
    //
    // The stub mirrors what `fetch` does with an aborted signal — reject — and
    // checks `aborted` BEFORE subscribing, because an already-aborted signal
    // never fires another `abort` event, and a listener-only stub would hang.
    const controller = new AbortController();
    controller.abort();

    const signals: AbortSignal[] = [];
    const client: LlmClient = {
      model: 'stub-model',
      complete: (_request, signal) =>
        new Promise<string>((_resolve, reject) => {
          signals.push(signal);
          if (signal.aborted) {
            reject(new Error('the request was aborted'));
            return;
          }
          signal.addEventListener('abort', () => reject(new Error('the request was aborted')));
        }),
    };

    await expect(
      runRemoteScan({
        diff: TWO_FILE_DIFF,
        credentials: CREDENTIALS,
        remote: REMOTE,
        client,
        signal: controller.signal,
      }),
    ).rejects.toThrow();

    expect(signals).toHaveLength(1);
    expect(signals[0]?.aborted).toBe(true);
  });

  it('bounds each request with its own timeout, independently of the caller', async () => {
    // The timeout is what stops one slow provider call from hanging a commit, so
    // it has to be on the signal even when the caller supplied none.
    const seen: AbortSignal[] = [];
    const client: LlmClient = {
      model: 'stub-model',
      complete: (_request, signal) => {
        seen.push(signal);
        // Unused, but keeping the promise pending would hang the suite; the
        // assertion is about the signal's shape, not about waiting it out.
        return Promise.resolve('{"findings":[]}');
      },
    };

    await runRemoteScan({
      diff: TWO_FILE_DIFF,
      credentials: CREDENTIALS,
      remote: { ...REMOTE, timeoutMs: 1_000 },
      client,
    });

    expect(seen).toHaveLength(1);
    // No external signal was passed, so this is the bare timeout signal.
    expect(seen[0]?.aborted).toBe(false);
  });
});
