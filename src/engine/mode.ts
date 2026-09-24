/**
 * Mode detection (FR-3, PRD §6.3).
 *
 * ─── "Present AND reachable" ─────────────────────────────────────────────────
 * FR-3 says to detect the mode from API key presence *and reachability*. This
 * module checks presence only, and that is not a shortcut: a pre-flight
 * reachability probe would cost a round trip on every scan and would still not
 * prove the next call succeeds. The first real call establishes reachability
 * better than any probe, and the pipeline treats its failure as the fallback
 * trigger (PRD §6.3: "if API call fails ... fallback to Local Mode + warn").
 *
 * So the flow is: presence chooses the attempt, the attempt decides the outcome.
 *
 * ─── The key is never returned to a caller that might print it ───────────────
 * The decision carries the key only in the `remote` variant, where the pipeline
 * needs it to build a request. Every place the key could reach output — the
 * `reason` string, error messages — carries a description instead. FR-10 is not
 * satisfied by remembering not to log something.
 */

import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { parse as parseDotEnv } from 'dotenv';

import type { HookMode } from '../config/schema';
import { DEFAULT_MODEL } from './remote/client';

/** Environment variable holding the key. Named in docs and errors, never its value. */
export const API_KEY_VAR = 'DEEPSEEK_API_KEY';

/**
 * Overrides the model id without editing a committed config file.
 *
 * This exists because a model id is the one setting most likely to be wrong for
 * reasons outside this project's control. It comes from the provider, it varies
 * by account, and it changes: `deepseek-v4.1-flash` had to become
 * `deepseek-flash` after the live API rejected the former, having got the name
 * from documentation that was simply wrong for the account in use. A wrong id
 * fails with a 400 that names the ones the endpoint does accept, and with this
 * variable the correction is one line in `.env` rather than a code change and a
 * release.
 */
export const MODEL_VAR = 'CODEGUARD_MODEL';

/**
 * Points the client at a different endpoint.
 *
 * Two uses, one of which is the reason it exists. The obvious one is a
 * self-hosted or proxied gateway. The important one is testing: without it, the
 * only way to exercise the real HTTP client — real `fetch`, real request body,
 * real response parsing, real error handling — is to hold a live provider key
 * and spend money on every run. With it, the whole path can be verified against
 * a local server holding canned answers.
 *
 * Note what this does NOT do: it cannot make CodeGuard transmit a diff anywhere
 * the user did not explicitly configure. Setting it is a deliberate act, and the
 * scan header still names the engine that ran.
 */
export const BASE_URL_VAR = 'CODEGUARD_BASE_URL';

export interface Environment {
  /** The effective environment: the `.env` file merged under the real process env. */
  env: NodeJS.ProcessEnv;
  /** Absolute path of the `.env` file that was read, or null when there was none. */
  envFile: string | null;
  /** Variables that came from that file rather than from the process. */
  fromFile: readonly string[];
}

/**
 * Reads `<repoRoot>/.env` and merges it UNDER the process environment.
 *
 * The process wins on conflict. An explicitly exported variable is a deliberate
 * act — `DEEPSEEK_API_KEY=... codeguard scan` — and a stale `.env` sitting in a
 * checkout must not be able to silently override it.
 *
 * Returns a copy rather than calling `dotenv.config()`, which mutates
 * `process.env` for the rest of the process. A CLI can get away with that; a
 * test suite cannot, because the first test to load a fixture `.env` would leak
 * its key into every later test.
 *
 * A missing or unreadable `.env` is the normal case and is not an error — PRD
 * §6.3 calls the keyless state "a supported default, not an error".
 */
export async function loadEnvironment(
  repoRoot: string,
  processEnv: NodeJS.ProcessEnv = process.env,
): Promise<Environment> {
  const envFile = path.join(repoRoot, '.env');

  let parsed: Record<string, string>;
  try {
    parsed = parseDotEnv(await readFile(envFile, 'utf8'));
  } catch {
    return { env: processEnv, envFile: null, fromFile: [] };
  }

  const fromFile = Object.keys(parsed).filter(
    (name) => processEnv[name] === undefined && parsed[name] !== undefined && parsed[name] !== '',
  );

  // Built by hand rather than spread, so a key present in the process with an
  // `undefined` value cannot overwrite the file's value with nothing.
  const env: NodeJS.ProcessEnv = { ...parsed, ...processEnv };
  for (const name of Object.keys(env)) {
    if (env[name] === undefined && parsed[name] !== undefined) env[name] = parsed[name];
  }

  return { env, envFile, fromFile };
}

export interface RemoteCredentials {
  apiKey: string;
  model: string;
  /** Overridden provider endpoint, when `CODEGUARD_BASE_URL` is set. */
  baseUrl?: string;
}

/**
 * Why Local Mode was chosen.
 *
 * Carried alongside the reason string because the string is written for a human
 * and programs should not have to read prose to find out what happened.
 * `codeguard config` is the caller that needs it: "local rule engine" is the
 * same four words whether the developer passed `--local`, has no key, or set
 * `remote.hookMode`, and those are three quite different situations — in one of
 * them the AI engine is available and deliberately unused.
 */
export type LocalSource = 'flag' | 'no-key' | 'config';

export type ModeDecision =
  | { kind: 'local'; reason: string; source: LocalSource }
  | { kind: 'remote'; reason: string; credentials: RemoteCredentials }
  /**
   * The user asked for something that cannot be honoured — currently only
   * `--remote` with no key. This is an error rather than a fallback on purpose:
   * falling back would give them a rule-based scan they did not ask for while
   * the flag implied an AI one.
   */
  | { kind: 'error'; message: string };

export interface ModeOptions {
  /** `--local`. */
  local?: boolean;
  /** `--remote`. */
  remote?: boolean;
  environment: Environment;
  /** `model` from `.codeguardrc.json`, if set. */
  configModel?: string;
  /**
   * `remote.hookMode` from `.codeguardrc.json`. Defaults to `"auto"`.
   *
   * Governs AUTOMATIC selection only. It is applied after the `--remote` branch
   * below, so an explicit flag always wins — a config file cannot veto a request
   * the user just typed.
   */
  hookMode?: HookMode;
}

/**
 * Decides which engine runs.
 *
 * Precedence, strongest first:
 *
 *   1. `--local` and `--remote` together — an error, not a choice.
 *   2. `--local`                    — honoured even when a key is present.
 *   3. `--remote`                   — an error without a key, never a fallback.
 *   4. no key                       — Local.
 *   5. `remote.hookMode: "local-only"` — Local, key or no key.
 *   6. otherwise                    — Remote.
 *
 * Steps 5 and 6 are the only ones a config file can move, and they are
 * deliberately below the flags: configuration decides what happens by DEFAULT,
 * and the command line decides what happens NOW. Reversing that would let a
 * repository's committed config silently override a developer who typed
 * `--remote`, which is the wrong way round for a setting whose whole purpose is
 * to be an escape hatch.
 *
 * Precedence for the model id: `CODEGUARD_MODEL` > config `model` > built-in
 * default. The environment variable is deliberately strongest — it is the escape
 * hatch for trying a different model against someone else's repository without
 * editing a file that is committed to it.
 */
export function decideMode(options: ModeOptions): ModeDecision {
  const { env, envFile, fromFile } = options.environment;

  const rawKey = env[API_KEY_VAR];
  const apiKey = typeof rawKey === 'string' && rawKey.trim() !== '' ? rawKey.trim() : null;
  const model = env[MODEL_VAR] ?? options.configModel ?? DEFAULT_MODEL;

  const rawBaseUrl = env[BASE_URL_VAR];
  const baseUrl =
    typeof rawBaseUrl === 'string' && rawBaseUrl.trim() !== '' ? rawBaseUrl.trim() : undefined;
  const credentials: RemoteCredentials = { apiKey: apiKey ?? '', model, ...(baseUrl === undefined ? {} : { baseUrl }) };

  if (options.local === true && options.remote === true) {
    return {
      kind: 'error',
      message: '--local and --remote cannot be combined; pick one, or omit both to auto-detect.',
    };
  }

  if (options.local === true) {
    return { kind: 'local', source: 'flag', reason: 'Local Mode forced by --local.' };
  }

  if (options.remote === true) {
    if (apiKey === null) {
      return {
        kind: 'error',
        message:
          `--remote requires ${API_KEY_VAR}. Set it, or copy .env.example to .env and fill it in. ` +
          'Run without --remote to use the local rule engine instead.',
      };
    }
    return {
      kind: 'remote',
      reason: `Remote Mode forced by --remote (${API_KEY_VAR} is set).`,
      credentials,
    };
  }

  if (apiKey === null) {
    return {
      kind: 'local',
      source: 'no-key',
      reason: `${API_KEY_VAR} is not set, so Local Mode is the default (PRD §6.3).`,
    };
  }

  // Checked after the keyless branch so the reason names the real cause: a
  // developer with no key and hookMode "local-only" is in Local Mode for the
  // ordinary reason, and telling them their config did it would send them
  // looking for a setting that is not the one in the way.
  //
  // Note what this does NOT do: there is no fallback here, because there is
  // nothing to fall back FROM. Nothing was attempted and nothing failed.
  if (options.hookMode === 'local-only') {
    return {
      kind: 'local',
      source: 'config',
      reason:
        `remote.hookMode is "local-only", so the automatic scan uses Local Mode even though ` +
        `${API_KEY_VAR} is set. Run \`codeguard scan --remote\` for an AI scan.`,
    };
  }

  const origin = fromFile.includes(API_KEY_VAR) && envFile !== null ? ` from ${envFile}` : '';
  return {
    kind: 'remote',
    reason: `${API_KEY_VAR} is set${origin}, so Remote Mode was selected.`,
    credentials,
  };
}
