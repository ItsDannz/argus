/**
 * The provider client.
 *
 * Two things are worth testing here and nothing else is. The first is the
 * reasoning flag, because it is the one field whose wrong value is invisible at
 * runtime: a Stage-1 request with thinking left on still succeeds, still returns
 * usable JSON, and merely costs several times what it should. Nothing about the
 * output reveals it.
 *
 * The second is FR-10 — the API key must never be printed. That is asserted
 * against an adversarial provider that echoes the credential back inside its
 * error body, because "we do not log the key" is a claim about the failure paths,
 * and the failure paths are exactly where it gets logged.
 */

import { describe, expect, it } from '@jest/globals';

import { buildRequestBody, createDeepSeekClient, DEFAULT_MODEL, LlmError } from '../client';

const KEY = 'sk-live-9f2b7c41d8e35a60b4c7f1e2';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    statusText: status === 200 ? 'OK' : 'Bad Request',
    headers: { 'Content-Type': 'application/json' },
  });
}

/** A client wired to a canned response, recording what it was asked to fetch. */
function clientWith(
  response: Response | (() => Promise<never>),
): { client: ReturnType<typeof createDeepSeekClient>; calls: { url: string; init: RequestInit }[] } {
  const calls: { url: string; init: RequestInit }[] = [];
  const client = createDeepSeekClient({
    apiKey: KEY,
    fetchImpl: (async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      if (typeof response === 'function') return response();
      return response;
    }) as typeof fetch,
  });
  return { client, calls };
}

const REQUEST = { system: 'system', user: 'user', reasoning: false };

describe('buildRequestBody', () => {
  it('turns thinking OFF for a Stage-1 request, explicitly', () => {
    // The trap: DeepSeek's thinking mode is ON BY DEFAULT at effort `high`. A
    // Stage-1 body that simply omitted the parameter would be a reasoning call
    // wearing a triage label, and the whole two-stage cost design would be
    // inverted while every test that only checked the JSON still passed.
    const body = buildRequestBody(DEFAULT_MODEL, { ...REQUEST, reasoning: false });

    expect(body['thinking']).toEqual({ type: 'disabled' });
    expect(body).not.toHaveProperty('reasoning_effort');
  });

  it('turns thinking ON for a Stage-2 request', () => {
    const body = buildRequestBody(DEFAULT_MODEL, { ...REQUEST, reasoning: true });

    expect(body['thinking']).toEqual({ type: 'enabled' });
    expect(body['reasoning_effort']).toBe('high');
  });

  it('sends the prompt as a system/user pair and demands a JSON object', () => {
    const body = buildRequestBody('some-model', { ...REQUEST, reasoning: true });

    expect(body['model']).toBe('some-model');
    expect(body['messages']).toEqual([
      { role: 'system', content: 'system' },
      { role: 'user', content: 'user' },
    ]);
    expect(body['response_format']).toEqual({ type: 'json_object' });
    expect(body['stream']).toBe(false);
  });

  it('caps output tokens, and lets a caller raise the cap', () => {
    const byDefault = buildRequestBody('m', REQUEST);
    const raised = buildRequestBody('m', { ...REQUEST, maxOutputTokens: 10 });

    expect(byDefault['max_tokens']).toBe(4096);
    expect(raised['max_tokens']).toBe(10);
  });

  it('omits sampling parameters that thinking mode ignores', () => {
    // Sending `temperature: 0` would advertise a determinism this call does not
    // have — DeepSeek silently ignores it in thinking mode. A field that lies is
    // worse than a missing field.
    const body = buildRequestBody('m', REQUEST);

    expect(body).not.toHaveProperty('temperature');
    expect(body).not.toHaveProperty('top_p');
    expect(body).not.toHaveProperty('presence_penalty');
    expect(body).not.toHaveProperty('frequency_penalty');
  });
});

describe('createDeepSeekClient', () => {
  it('posts to /chat/completions with a bearer token and returns the content', async () => {
    const { client, calls } = clientWith(
      jsonResponse({ choices: [{ message: { content: '{"findings":[]}' } }] }),
    );

    await expect(client.complete(REQUEST, new AbortController().signal)).resolves.toBe(
      '{"findings":[]}',
    );
    expect(calls[0]?.url).toBe('https://api.deepseek.com/chat/completions');
    expect((calls[0]?.init.headers as Record<string, string>)['Authorization']).toBe(`Bearer ${KEY}`);
  });

  it('ignores reasoning_content, which is not the answer', async () => {
    const { client } = clientWith(
      jsonResponse({
        choices: [{ message: { reasoning_content: 'Let me think about this…', content: '{"findings":[]}' } }],
      }),
    );

    await expect(client.complete(REQUEST, new AbortController().signal)).resolves.toBe(
      '{"findings":[]}',
    );
  });

  it('reports the model it was built with, without branching on it', () => {
    expect(createDeepSeekClient({ apiKey: KEY }).model).toBe(DEFAULT_MODEL);
    expect(createDeepSeekClient({ apiKey: KEY, model: 'other' }).model).toBe('other');
  });

  it('allows the base URL to be pointed elsewhere', async () => {
    const calls: string[] = [];
    const client = createDeepSeekClient({
      apiKey: KEY,
      baseUrl: 'http://localhost:8080/',
      fetchImpl: (async (url: string | URL | Request) => {
        calls.push(String(url));
        return jsonResponse({ choices: [{ message: { content: '{}' } }] });
      }) as typeof fetch,
    });

    await client.complete(REQUEST, new AbortController().signal);
    // The trailing slash is trimmed, so the path does not double up.
    expect(calls[0]).toBe('http://localhost:8080/chat/completions');
  });
});

describe('failures never leak the credential (FR-10)', () => {
  it('strips the key even when the provider echoes it back in an error body', async () => {
    const { client } = clientWith(
      jsonResponse({ error: { message: `Invalid key: ${KEY}` } }, 401),
    );

    const error = await client.complete(REQUEST, new AbortController().signal).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(LlmError);
    expect((error as LlmError).status).toBe(401);
    const message = (error as Error).message;
    expect(message).not.toContain(KEY);
    expect(message).toContain('401');
  });

  it('strips the key from a non-JSON error page', async () => {
    const { client } = clientWith(
      new Response(`<html>Forbidden for token ${KEY}</html>`, { status: 403, statusText: 'Forbidden' }),
    );

    const error = (await client
      .complete(REQUEST, new AbortController().signal)
      .catch((e: unknown) => e)) as Error;

    expect(error.message).not.toContain(KEY);
  });

  it('strips the key from a network-level failure', async () => {
    const { client } = clientWith(() =>
      Promise.reject(new Error(`connect ECONNREFUSED with header Bearer ${KEY}`)),
    );

    const error = (await client
      .complete(REQUEST, new AbortController().signal)
      .catch((e: unknown) => e)) as Error;

    expect(error).toBeInstanceOf(LlmError);
    expect(error.message).not.toContain(KEY);
    expect(error.message).toContain('could not reach');
  });

  it('does not put the key in the request body', async () => {
    const { client, calls } = clientWith(
      jsonResponse({ choices: [{ message: { content: '{}' } }] }),
    );

    await client.complete(REQUEST, new AbortController().signal);

    expect(String(calls[0]?.init.body)).not.toContain(KEY);
  });
});

describe('responses that are not usable', () => {
  it('rejects a non-JSON body', async () => {
    const { client } = clientWith(new Response('<html>gateway</html>', { status: 200 }));

    await expect(client.complete(REQUEST, new AbortController().signal)).rejects.toThrow(
      /non-JSON body/,
    );
  });

  it('rejects a response with no message content', async () => {
    const { client } = clientWith(jsonResponse({ choices: [{ message: {} }] }));

    await expect(client.complete(REQUEST, new AbortController().signal)).rejects.toThrow(
      /nothing usable/,
    );
  });

  it('rejects whitespace-only content', async () => {
    const { client } = clientWith(jsonResponse({ choices: [{ message: { content: '   \n ' } }] }));

    await expect(client.complete(REQUEST, new AbortController().signal)).rejects.toThrow(
      /nothing usable/,
    );
  });
});
