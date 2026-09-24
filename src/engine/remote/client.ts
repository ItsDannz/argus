/**
 * The AI provider client (PRD §6.1, §9.1).
 *
 * NFR Extensibility: "AI provider integration should be abstracted behind an
 * interface so other providers (OpenAI, Anthropic, local LLMs) can be added
 * later without rewriting core logic." `LlmClient` is that interface, and it is
 * deliberately the smallest thing that could work — one method, text in, text
 * out. Everything CodeGuard does with a model (triage, patch generation) is
 * prompt construction and response parsing, and both of those live outside this
 * file. Swapping in another provider means writing one more factory.
 *
 * No SDK is used, on purpose. PRD §9.1's stack does not name one, Node 22 has
 * `fetch`, and the request is a single JSON POST. A dependency here would buy
 * nothing and would be one more place for a credential to end up logged.
 */

import { redactApiKey } from './redact';

export interface LlmRequest {
  system: string;
  user: string;
  /**
   * Whether the provider should spend reasoning tokens on this request.
   *
   * This is the entire two-stage cost control (PRD §6.1): the same model, the
   * same endpoint, asked for triage without thinking and for deep analysis with
   * it. It is a per-request flag rather than two model names because the
   * `deepseek-chat` / `deepseek-reasoner` aliases are retired.
   */
  reasoning: boolean;
  /** Upper bound on the answer. Patches are small; the JSON envelope is not. */
  maxOutputTokens?: number;
}

export interface LlmClient {
  /** Model id, for reporting. Never branched on. */
  readonly model: string;
  /**
   * @param signal Aborts the request. The caller owns the timeout so a slow
   *               provider degrades to Local Mode rather than hanging a commit.
   */
  complete(request: LlmRequest, signal: AbortSignal): Promise<string>;
}

export const DEFAULT_BASE_URL = 'https://api.deepseek.com';

/**
 * The model id both stages run on, when nothing overrides it.
 *
 * ─── Where this value came from ──────────────────────────────────────────────
 * From the provider's own 400 response, not from documentation. This constant
 * previously read `deepseek-v4.1-flash`, taken from external docs that were
 * wrong for the account in use; the API rejected it with
 * `invalid_request_error` and listed the names it does accept — `deepseek-flash`
 * and `deepseek-v4-pro` — and that list is the only one authoritative for the
 * endpoint actually being called.
 *
 * The lesson generalises past this one string. A model id is not a fact about
 * DeepSeek; it is a fact about an account on an endpoint, and it can differ by
 * region, by plan, and over time. So it is a value to be overridden and never a
 * value to be re-derived from a blog post — hence `CODEGUARD_MODEL` (see
 * engine/mode.ts) and the config `model` key, which resolve before this
 * constant is consulted. If a future scan starts failing with a 400 and a list
 * of names, the fix is one line in `.env`, not a code change.
 */
export const DEFAULT_MODEL = 'deepseek-flash';

/**
 * How reasoning is requested, per DeepSeek's Thinking Mode guide.
 *
 * Verified against the API documentation rather than guessed, and the detail
 * that matters is that THINKING IS ON BY DEFAULT at effort `high`. Stage 1
 * therefore has to switch it OFF explicitly — a stage-1 request that merely
 * omitted the parameter would silently be a reasoning call, which inverts the
 * whole cost design while looking perfectly correct in the code.
 *
 * With the official OpenAI SDK these fields must be passed inside `extra_body`.
 * This client posts raw JSON, so they belong at the top level of the body, which
 * is what the documented request example shows.
 */
const THINKING_ON = { thinking: { type: 'enabled' }, reasoning_effort: 'high' } as const;
const THINKING_OFF = { thinking: { type: 'disabled' } } as const;

/** A conservative ceiling: a patch plus its JSON envelope, not an essay. */
const DEFAULT_MAX_OUTPUT_TOKENS = 4096;

/**
 * Builds the request body.
 *
 * Exported and pure so it can be asserted on directly — the reasoning flag is
 * the one place a wrong value is invisible at runtime (the request still
 * succeeds, it is just expensive and mislabelled) and the one place this
 * project cannot test against the live API on demand.
 *
 * `temperature`, `top_p`, `presence_penalty` and `frequency_penalty` are
 * deliberately absent. DeepSeek silently ignores the first three in thinking
 * mode and floors `top_p` at 0.95, so sending them would advertise a
 * determinism this call does not have.
 */
export function buildRequestBody(model: string, request: LlmRequest): Record<string, unknown> {
  return {
    model,
    messages: [
      { role: 'system', content: request.system },
      { role: 'user', content: request.user },
    ],
    // Both prompts demand strict JSON with no prose wrapper, and the parser
    // strips fences anyway. DeepSeek's JSON mode requires the word "json" to
    // appear in the prompt, which both of our prompts do.
    response_format: { type: 'json_object' },
    stream: false,
    max_tokens: request.maxOutputTokens ?? DEFAULT_MAX_OUTPUT_TOKENS,
    ...(request.reasoning ? THINKING_ON : THINKING_OFF),
  };
}

/** The subset of the OpenAI-shaped response we rely on. */
interface ChatCompletionResponse {
  choices?: { message?: { content?: string; reasoning_content?: string } }[];
  error?: { message?: string };
}

export interface DeepSeekClientOptions {
  apiKey: string;
  model?: string;
  baseUrl?: string;
  /** Injectable for tests. Defaults to the global `fetch`. */
  fetchImpl?: typeof fetch;
}

/**
 * How the request failed, for callers that have to behave differently per case.
 *
 *   transport  the provider was never reached
 *   http       the provider answered with a non-2xx
 *   malformed  the provider answered, but not with the JSON envelope we expect
 *   empty      a well-formed envelope with no message content in it
 *
 * The distinction exists because one of these is worth retrying and the others
 * are not — see `isEmptyAnswer` in remote/index.ts. `empty` is the odd one out:
 * it is not a statement about the request, the credential, or the endpoint, all
 * of which are unchanged a second later, so a repeat costs one request and may
 * well work. The other three are answers, and asking again gets the same answer.
 */
export type LlmFailureKind = 'transport' | 'http' | 'malformed' | 'empty';

/**
 * A failure talking to the provider.
 *
 * Carries no request detail — the request headers hold the API key, and an
 * error object is exactly the sort of thing that gets `JSON.stringify`d into a
 * log line. The message is run through `redactApiKey` before it is stored, so
 * even a provider that echoes the credential back cannot get it printed.
 */
export class LlmError extends Error {
  constructor(
    message: string,
    readonly kind: LlmFailureKind = 'transport',
    readonly status?: number,
  ) {
    super(message);
    this.name = 'LlmError';
  }
}

export function createDeepSeekClient(options: DeepSeekClientOptions): LlmClient {
  const model = options.model ?? DEFAULT_MODEL;
  const baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
  const doFetch = options.fetchImpl ?? fetch;

  return {
    model,

    async complete(request: LlmRequest, signal: AbortSignal): Promise<string> {
      const safe = (text: string): string => redactApiKey(text, options.apiKey);

      let response: Response;
      try {
        response = await doFetch(`${baseUrl}/chat/completions`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${options.apiKey}`,
          },
          body: JSON.stringify(buildRequestBody(model, request)),
          signal,
        });
      } catch (error) {
        // Network failure, DNS failure, or the caller's timeout firing. The
        // caller decides that this means Local Mode; the message says what
        // happened without saying what was sent.
        const message = error instanceof Error ? error.message : String(error);
        throw new LlmError(`could not reach ${baseUrl} — ${safe(message)}`);
      }

      const text = await response.text();

      if (!response.ok) {
        // Providers often put a useful reason in the body; truncate it so a
        // 404 HTML page cannot flood the terminal.
        throw new LlmError(
          `provider returned ${response.status} ${response.statusText} — ${safe(text.slice(0, 300))}`,
          'http',
          response.status,
        );
      }

      let parsed: ChatCompletionResponse;
      try {
        parsed = JSON.parse(text) as ChatCompletionResponse;
      } catch {
        throw new LlmError(
          `provider returned a non-JSON body — ${safe(text.slice(0, 300))}`,
          'malformed',
        );
      }

      // `content` is the answer; `reasoning_content` is the chain of thought and
      // is deliberately ignored. We send no `tools`, so there is no obligation
      // to echo it back on a later turn.
      const content = parsed.choices?.[0]?.message?.content;
      if (typeof content !== 'string' || content.trim() === '') {
        const reason = parsed.error?.message ?? 'the response contained no message content';
        // `empty`, not `transport`: the call worked. Observed live — the same
        // request succeeded moments earlier and succeeded again on a repeat,
        // which is what makes this the one failure worth retrying.
        throw new LlmError(`provider returned nothing usable — ${safe(reason)}`, 'empty');
      }

      return content;
    },
  };
}
