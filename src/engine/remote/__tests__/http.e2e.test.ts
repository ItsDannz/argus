/**
 * The real HTTP path, against a real server (Phase 4 acceptance criterion).
 *
 * Phase 4's stated acceptance criterion is that a scan against the live API
 * returns a structured finding and a patch. That cannot be run unattended — it
 * needs a provider key, it costs money, and it makes the suite fail whenever
 * DeepSeek has a bad afternoon. Neither can it simply be skipped, because then
 * the entire HTTP surface goes unverified: the request body, the bearer header,
 * the response envelope, the non-200 path, the timeout.
 *
 * So this file stands up an actual HTTP server on a loopback port and points the
 * real client at it. Everything except the provider's own reasoning is exercised
 * for real — `fetch`, JSON encoding, header handling, status codes, aborts. The
 * only thing stubbed is the answer text.
 *
 * The same `CODEGUARD_BASE_URL` hook that makes this test possible lets a user
 * point CodeGuard at a gateway or a local model, which is why it is a supported
 * setting rather than a test-only escape hatch.
 */

import { createServer, type Server } from 'node:http';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';

import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';

import { runRemoteScan } from '../index';

const KEY = 'sk-live-9f2b7c41d8e35a60b4c7f1e2';

const DIFF = [
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

/** The triage answer, in exactly the shape the prompt demands. */
const TRIAGE_ANSWER = JSON.stringify({
  findings: [
    {
      file: 'src/db.js',
      line_range: [2, 2],
      severity: 'Critical',
      category: 'sql_injection',
      summary: 'Request data is concatenated into a SQL query.',
    },
  ],
});

/** The deep-analysis answer, with a unified diff as the patch. */
const PATCH_ANSWER = JSON.stringify({
  file: 'src/db.js',
  line_range: [2, 2],
  severity: 'Critical',
  category: 'sql_injection',
  explanation: 'The concatenated value is parsed as SQL, so the caller controls the query.',
  suggested_patch: [
    '--- a/src/db.js',
    '+++ b/src/db.js',
    '@@ -1,3 +1,3 @@',
    ' function findUser(db, name) {',
    '-  const sql = "SELECT * FROM users WHERE name = " + name;',
    '+  const sql = "SELECT * FROM users WHERE name = ?";',
    '-  return db.query(sql);',
    '+  return db.query(sql, [name]);',
    ' }',
  ].join('\n'),
  confidence: 'high',
});

interface Received {
  url: string;
  authorization: string | undefined;
  body: Record<string, unknown>;
}

/** What the next request should get back, so failure paths can be driven. */
interface Behaviour {
  status?: number;
  statusText?: string;
  /** Reply to triage with this, and to deep analysis with the patch answer. */
  triage?: string;
  patch?: string;
  /** Called before replying, to simulate a slow or hanging provider. */
  delayMs?: number;
}

let server: Server;
let baseUrl = '';
const received: Received[] = [];
let behaviour: Behaviour = {};
/** Timers from the delayed-response test, cleared so Jest can exit. */
const pendingTimers: NodeJS.Timeout[] = [];

/**
 * Credentials for the loopback server.
 *
 * A FUNCTION, not a constant, and that is load-bearing. `baseUrl` is only known
 * once the server is listening, so a module-level object literal captures it as
 * `undefined` — and the client then falls back to `DEFAULT_BASE_URL`, sending
 * the test's requests to the real DeepSeek endpoint. That happened while writing
 * this file: the suite made unauthenticated calls to api.deepseek.com and failed
 * with a provider 401 rather than a test error.
 */
function credentials(): { apiKey: string; model: string; baseUrl: string } {
  if (baseUrl === '') throw new Error('the test server is not listening yet');
  return { apiKey: KEY, model: 'deepseek-flash', baseUrl };
}

/**
 * Guards against a repeat of the above.
 *
 * Every test must reach the loopback server at least once. If a future change
 * points the client somewhere else, `received` stays empty and this fails —
 * loudly and locally, instead of the suite quietly talking to a third party.
 */
function assertReachedOurServer(): void {
  if (received.length === 0) {
    throw new Error('no request reached the test server — was this sent to a real provider?');
  }
}

beforeAll(async () => {
  server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      let body: Record<string, unknown> = {};
      try {
        body = JSON.parse(raw) as Record<string, unknown>;
      } catch {
        // Left empty; the assertions will show the body was not JSON.
      }

      received.push({
        url: request.url ?? '',
        authorization: request.headers.authorization,
        body,
      });

      const messages = (body['messages'] ?? []) as { content?: string }[];
      const system = messages[0]?.content ?? '';
      const answer = system.includes('triage engine')
        ? (behaviour.triage ?? TRIAGE_ANSWER)
        : (behaviour.patch ?? PATCH_ANSWER);

      const reply = (): void => {
        response.writeHead(behaviour.status ?? 200, behaviour.statusText ?? 'OK', {
          'Content-Type': 'application/json',
        });
        response.end(
          (behaviour.status ?? 200) === 200
            ? JSON.stringify({ choices: [{ message: { content: answer } }] })
            : JSON.stringify({ error: { message: answer } }),
        );
      };

      if (behaviour.delayMs !== undefined) {
        // Tracked so the timeout test's pending timer can be cleared, and the
        // socket it holds released. Without this, Jest finishes the run and then
        // hangs on an open handle.
        const timer = setTimeout(reply, behaviour.delayMs);
        pendingTimers.push(timer);
      } else {
        reply();
      }
    });
  });

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  for (const timer of pendingTimers) clearTimeout(timer);
  // The timeout test abandons a request mid-flight, which leaves a socket open.
  // Closing connections explicitly is what lets the process exit.
  server.closeAllConnections();
  server.close();
  await once(server, 'close');
});

const REMOTE = { maxDeepAnalysisHunks: 5, timeoutMs: 5_000 };

describe('a full remote scan over real HTTP', () => {
  it('completes both stages and returns a finding plus a patch', async () => {
    // The Phase 4 acceptance criterion, as close as it can be run unattended:
    // structured finding AND patch suggestion, from a real HTTP exchange.
    received.length = 0;
    behaviour = {};

    const outcome = await runRemoteScan({
      diff: DIFF,
      credentials: credentials(),
      remote: REMOTE,
    });

    expect(outcome.findings).toHaveLength(1);
    expect(outcome.findings[0]).toMatchObject({
      file: 'src/db.js',
      line: 2,
      ruleId: 'sql_injection',
      severity: 'Critical',
    });
    expect(outcome.analyses).toHaveLength(1);
    expect(outcome.analyses[0]?.patch).toContain('db.query(sql, [name])');
    expect(outcome.analyses[0]?.confidence).toBe('high');
    expect(outcome.requestCount).toBe(2);
    assertReachedOurServer();
  });

  it('posts to /chat/completions with the bearer token and both messages', async () => {
    received.length = 0;
    behaviour = {};

    await runRemoteScan({ diff: DIFF, credentials: credentials(), remote: REMOTE });

    expect(received).toHaveLength(2);
    expect(received[0]?.url).toBe('/chat/completions');
    expect(received[0]?.authorization).toBe(`Bearer ${KEY}`);
    const messages = received[0]?.body['messages'] as { role: string }[];
    expect(messages.map((message) => message.role)).toEqual(['system', 'user']);
    expect(received[0]?.body['response_format']).toEqual({ type: 'json_object' });
    assertReachedOurServer();
  });

  it('asks the provider for thinking on the second stage only', async () => {
    // On the wire, not just in the request builder. This is the cost design, and
    // it is the kind of thing a refactor can invert without failing anything.
    received.length = 0;
    behaviour = {};

    await runRemoteScan({ diff: DIFF, credentials: credentials(), remote: REMOTE });

    expect(received[0]?.body['thinking']).toEqual({ type: 'disabled' });
    expect(received[1]?.body['thinking']).toEqual({ type: 'enabled' });
    expect(received[1]?.body['reasoning_effort']).toBe('high');
    assertReachedOurServer();
  });

  it('never puts the API key in a request body', async () => {
    received.length = 0;
    behaviour = {};

    await runRemoteScan({ diff: DIFF, credentials: credentials(), remote: REMOTE });

    for (const request of received) {
      expect(JSON.stringify(request.body)).not.toContain(KEY);
    }
    assertReachedOurServer();
  });

  it('redacts a secret before the request leaves the process', async () => {
    // FR-10 and NFR §8, asserted at the socket rather than at the function.
    received.length = 0;
    behaviour = { triage: '{"findings":[]}' };

    const secretDiff = DIFF.replace(
      '+  return db.query(sql);',
      '+  const token = "ghp_9f2b7c41d8e35a60b4c7f1e2d4a6b8c0e2f4a6b8c0";',
    );

    await runRemoteScan({ diff: secretDiff, credentials: credentials(), remote: REMOTE });

    const sent = JSON.stringify(received[0]?.body);
    expect(sent).not.toContain('ghp_9f2b7c41d8e35a60b4c7f1e2d4a6b8c0e2f4a6b8c0');
    expect(sent).toContain('REDACTED');
    assertReachedOurServer();
  });
});

describe('provider failures over real HTTP', () => {
  it('throws so the caller can fall back when the provider errors', async () => {
    received.length = 0;
    behaviour = { status: 500, statusText: 'Internal Server Error', triage: 'upstream exploded' };

    await expect(
      runRemoteScan({ diff: DIFF, credentials: credentials(), remote: REMOTE }),
    ).rejects.toThrow(/500/);
    assertReachedOurServer();
  });

  it('does not leak the key when the provider echoes it in an error body', async () => {
    received.length = 0;
    behaviour = { status: 401, statusText: 'Unauthorized', triage: `bad key: ${KEY}` };

    const error = (await runRemoteScan({
      diff: DIFF,
      credentials: credentials(),
      remote: REMOTE,
    }).catch((thrown: unknown) => thrown)) as Error;

    expect(error.message).not.toContain(KEY);
    assertReachedOurServer();
  });

  it('gives up on a provider that never answers, rather than hanging the commit', async () => {
    // The timeout is what stops a stalled provider from blocking a `git commit`
    // indefinitely. 250ms is short enough to keep the suite fast and long enough
    // not to be a race.
    received.length = 0;
    behaviour = { delayMs: 2_000 };

    await expect(
      runRemoteScan({
        diff: DIFF,
        credentials: credentials(),
        remote: { ...REMOTE, timeoutMs: 250 },
      }),
    ).rejects.toThrow();
    assertReachedOurServer();
  });

  it('survives a provider that answers with something that is not JSON', async () => {
    received.length = 0;
    behaviour = { triage: 'Here is my analysis!' };

    await expect(
      runRemoteScan({ diff: DIFF, credentials: credentials(), remote: REMOTE }),
    ).rejects.toThrow(/not valid JSON/);
    assertReachedOurServer();
  });
});
