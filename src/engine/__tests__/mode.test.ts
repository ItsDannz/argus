/**
 * Mode detection (FR-3, PRD §6.3).
 *
 * Two rules carry the weight here.
 *
 * The first is precedence: an explicitly exported variable beats a `.env` file.
 * A stale `.env` sitting in a checkout must not silently override
 * `DEEPSEEK_API_KEY=... codeguard scan`, because the second is a deliberate act
 * and the first is usually forgotten.
 *
 * The second is that `--remote` without a key is an ERROR, not a fallback. The
 * developer asked for an AI scan; handing them a regex scan while the flag
 * implied otherwise is a lie about what ran.
 */

import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from '@jest/globals';

import { API_KEY_VAR, decideMode, loadEnvironment, MODEL_VAR } from '../mode';
import { DEFAULT_MODEL } from '../remote/client';

const KEY = 'sk-live-9f2b7c41d8e35a60b4c7f1e2';

const temporaryDirectories: string[] = [];

async function repoWithEnvFile(contents: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'codeguard-mode-'));
  temporaryDirectories.push(root);
  await writeFile(join(root, '.env'), contents, 'utf8');
  return root;
}

async function emptyRepo(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'codeguard-mode-'));
  temporaryDirectories.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

const environmentOf = (env: NodeJS.ProcessEnv): Awaited<ReturnType<typeof loadEnvironment>> => ({
  env,
  envFile: null,
  fromFile: [],
});

describe('loadEnvironment', () => {
  it('reads key/value pairs out of .env', async () => {
    const root = await repoWithEnvFile(`${API_KEY_VAR}=${KEY}\n`);

    const environment = await loadEnvironment(root, {});

    expect(environment.env[API_KEY_VAR]).toBe(KEY);
    expect(environment.envFile).toBe(join(root, '.env'));
    expect(environment.fromFile).toContain(API_KEY_VAR);
  });

  it('lets the process win over the file', async () => {
    const root = await repoWithEnvFile(`${API_KEY_VAR}=from-the-file\n`);

    const environment = await loadEnvironment(root, { [API_KEY_VAR]: 'from-the-process' });

    expect(environment.env[API_KEY_VAR]).toBe('from-the-process');
    expect(environment.fromFile).not.toContain(API_KEY_VAR);
  });

  it('does not mutate the process environment it was given', async () => {
    // `dotenv.config()` would write into `process.env` for the rest of the
    // process. A CLI can just about get away with that; a test suite cannot,
    // because the first test to load a fixture `.env` would leak its key into
    // every test that ran afterwards.
    const root = await repoWithEnvFile(`${API_KEY_VAR}=${KEY}\n`);
    const processEnv: NodeJS.ProcessEnv = {};

    await loadEnvironment(root, processEnv);

    expect(processEnv[API_KEY_VAR]).toBeUndefined();
  });

  it('treats a missing .env as the normal case, not an error', async () => {
    // PRD §6.3: the keyless state is "a supported default, not an error".
    const root = await emptyRepo();

    const environment = await loadEnvironment(root, {});

    expect(environment.envFile).toBeNull();
    expect(environment.fromFile).toEqual([]);
  });

  it('ignores an empty value in the file rather than treating it as set', async () => {
    const root = await repoWithEnvFile(`${API_KEY_VAR}=\n`);

    const environment = await loadEnvironment(root, {});

    expect(environment.fromFile).not.toContain(API_KEY_VAR);
  });

  it('keeps a process variable that the file does not mention', async () => {
    const root = await repoWithEnvFile('SOMETHING_ELSE=1\n');

    const environment = await loadEnvironment(root, { KEEP_ME: 'yes' });

    expect(environment.env['KEEP_ME']).toBe('yes');
    expect(environment.env['SOMETHING_ELSE']).toBe('1');
  });
});

describe('decideMode', () => {
  it('auto-detects Local Mode when there is no key', () => {
    const decision = decideMode({ environment: environmentOf({}) });

    expect(decision.kind).toBe('local');
    if (decision.kind === 'local') expect(decision.reason).toContain('not set');
  });

  it('auto-detects Remote Mode when the key is present', () => {
    const decision = decideMode({ environment: environmentOf({ [API_KEY_VAR]: KEY }) });

    expect(decision.kind).toBe('remote');
    if (decision.kind === 'remote') expect(decision.credentials.apiKey).toBe(KEY);
  });

  it('says where the key came from, without repeating it', () => {
    // FR-10 in the one place a helpful message would naturally include the
    // secret. The reason string is printed, so it names the variable and the
    // file and never the value.
    const decision = decideMode({
      environment: { env: { [API_KEY_VAR]: KEY }, envFile: '/repo/.env', fromFile: [API_KEY_VAR] },
    });

    expect(decision.kind).toBe('remote');
    if (decision.kind === 'remote') {
      expect(decision.reason).toContain('/repo/.env');
      expect(decision.reason).not.toContain(KEY);
    }
  });

  it('treats a whitespace-only key as absent', () => {
    expect(decideMode({ environment: environmentOf({ [API_KEY_VAR]: '   ' }) }).kind).toBe('local');
  });

  it('trims the key it passes on', () => {
    const decision = decideMode({ environment: environmentOf({ [API_KEY_VAR]: `  ${KEY}  ` }) });

    expect(decision.kind).toBe('remote');
    if (decision.kind === 'remote') expect(decision.credentials.apiKey).toBe(KEY);
  });

  it('honours --local even when a key is present', () => {
    const decision = decideMode({
      local: true,
      environment: environmentOf({ [API_KEY_VAR]: KEY }),
    });

    expect(decision.kind).toBe('local');
  });

  it('makes --remote without a key an error rather than a quiet fallback', () => {
    // The developer asked for an AI scan. Falling back would give them a
    // rule-based scan they did not ask for, while the flag implied otherwise —
    // and they would never know the AI pass did not run.
    const decision = decideMode({ remote: true, environment: environmentOf({}) });

    expect(decision.kind).toBe('error');
    if (decision.kind === 'error') {
      expect(decision.message).toContain(API_KEY_VAR);
      expect(decision.message).toContain('--remote');
    }
  });

  it('refuses --local and --remote together', () => {
    const decision = decideMode({
      local: true,
      remote: true,
      environment: environmentOf({ [API_KEY_VAR]: KEY }),
    });

    expect(decision.kind).toBe('error');
    if (decision.kind === 'error') expect(decision.message).toContain('cannot be combined');
  });

  it('honours --remote when a key is present', () => {
    const decision = decideMode({
      remote: true,
      environment: environmentOf({ [API_KEY_VAR]: KEY }),
    });

    expect(decision.kind).toBe('remote');
    if (decision.kind === 'remote') expect(decision.reason).toContain('--remote');
  });
});

describe('decideMode — remote.hookMode', () => {
  it('keeps an automatic scan local when hookMode is local-only, key or no key', () => {
    const decision = decideMode({
      environment: environmentOf({ [API_KEY_VAR]: KEY }),
      hookMode: 'local-only',
    });

    expect(decision.kind).toBe('local');
    if (decision.kind === 'local') {
      expect(decision.source).toBe('config');
      expect(decision.reason).toContain('local-only');
      // FR-10: the reason string is printed, so it names the variable and never
      // the value — and this message is written about a key that IS present.
      expect(decision.reason).not.toContain(KEY);
    }
  });

  it('lets --remote override hookMode, because a flag is a decision made now', () => {
    // A committed config must not veto the command somebody just typed. If it
    // could, "local-only" would be a setting you cannot escape without editing a
    // file — including in CI, where nothing else can change the mode.
    const decision = decideMode({
      remote: true,
      environment: environmentOf({ [API_KEY_VAR]: KEY }),
      hookMode: 'local-only',
    });

    expect(decision.kind).toBe('remote');
  });

  it('still reports a misspelled key as the reason when there is no key', () => {
    // With no key and local-only set, the config is not what put us in Local
    // Mode — the missing key is. Naming the config would send the developer
    // looking for a setting that is not in the way.
    const decision = decideMode({ environment: environmentOf({}), hookMode: 'local-only' });

    expect(decision.kind).toBe('local');
    if (decision.kind === 'local') {
      expect(decision.source).toBe('no-key');
      expect(decision.reason).toContain('not set');
    }
  });

  it('is the default when the config says nothing', () => {
    expect(decideMode({ environment: environmentOf({ [API_KEY_VAR]: KEY }) }).kind).toBe('remote');
  });

  it('changes nothing when it is explicitly "auto"', () => {
    const decision = decideMode({
      environment: environmentOf({ [API_KEY_VAR]: KEY }),
      hookMode: 'auto',
    });

    expect(decision.kind).toBe('remote');
  });

  it('does not stop --local being reported as the cause when both apply', () => {
    // Precedence is flag > config, and the reported cause has to match the
    // precedence or the message contradicts the behaviour.
    const decision = decideMode({
      local: true,
      environment: environmentOf({ [API_KEY_VAR]: KEY }),
      hookMode: 'local-only',
    });

    expect(decision.kind).toBe('local');
    if (decision.kind === 'local') expect(decision.source).toBe('flag');
  });
});

describe('model selection', () => {
  it('defaults to the built-in model', () => {
    const decision = decideMode({ environment: environmentOf({ [API_KEY_VAR]: KEY }) });

    if (decision.kind === 'remote') expect(decision.credentials.model).toBe(DEFAULT_MODEL);
  });

  it('prefers the config file over the default', () => {
    const decision = decideMode({
      environment: environmentOf({ [API_KEY_VAR]: KEY }),
      configModel: 'from-config',
    });

    if (decision.kind === 'remote') expect(decision.credentials.model).toBe('from-config');
  });

  it('prefers the environment over the config file', () => {
    // The escape hatch: try a different model against someone else's repository
    // without editing a file that is committed to it.
    const decision = decideMode({
      environment: environmentOf({ [API_KEY_VAR]: KEY, [MODEL_VAR]: 'from-environment' }),
      configModel: 'from-config',
    });

    if (decision.kind === 'remote') expect(decision.credentials.model).toBe('from-environment');
  });

  it('ignores a model override when the mode is Local', () => {
    // Nothing should leak a model id into a scan that never calls a model.
    const decision = decideMode({
      environment: environmentOf({ [MODEL_VAR]: 'from-environment' }),
      configModel: 'from-config',
    });

    expect(decision.kind).toBe('local');
  });
});
