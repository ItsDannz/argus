/**
 * Handing a patch to the developer's editor (FR-7: Accept, Reject, or EDIT).
 *
 * Deliberately the same pattern `git commit` and `git rebase -i` use: write the
 * text to a temporary file, hand over the terminal, read the file back. Two
 * reasons not to build anything cleverer — a custom in-terminal diff editor is a
 * project of its own, and every developer already knows how to use the editor
 * their $EDITOR points at.
 *
 * Nothing here decides whether the edited patch is any good. That is
 * `validatePatch`, and it is applied to the result by the caller. This module
 * only answers "what did the developer leave in the file".
 */

import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export type EditOutcome = { ok: true; text: string } | { ok: false; reason: string };

export interface EditorOptions {
  /** Injected for tests; defaults to `process.env`. */
  env?: NodeJS.ProcessEnv;
  /** Injected for tests; defaults to `process.platform`. */
  platform?: NodeJS.Platform;
  /** Injected so tests never launch an editor. */
  run?: (command: string) => { status: number | null; error?: Error };
}

/**
 * The editor to use, resolved the way Git resolves it.
 *
 * `VISUAL` before `EDITOR` because that is the POSIX convention and the order
 * Git uses; a developer who set both meant the more specific one. The fallback
 * is per-platform, and `notepad` is the honest answer on Windows: it is always
 * present, and blocking until it exits is what this needs.
 *
 * A BLANK value is treated as unset, not as a choice. `??` alone would not do
 * that — `VISUAL=''` is not nullish, so an `export VISUAL=` line in a shell
 * profile would have swallowed a perfectly good `EDITOR` and sent the developer
 * to `vi` without saying so.
 */
export function resolveEditor(env: NodeJS.ProcessEnv = process.env, platform: NodeJS.Platform = process.platform): string {
  const configured = [env.VISUAL, env.EDITOR].find(
    (value) => value !== undefined && value.trim() !== '',
  );
  return configured?.trim() ?? (platform === 'win32' ? 'notepad' : 'vi');
}

/**
 * Opens the editor on `patch` and returns what came back.
 *
 * The command is built as a shell line rather than an argv pair, so an
 * `EDITOR="code --wait"` keeps working — the same reason Git does it this way.
 * Only the path is quoted, which is the half that can contain a space on a
 * normal machine.
 */
export async function editInEditor(patch: string, options: EditorOptions = {}): Promise<EditOutcome> {
  const editor = resolveEditor(options.env, options.platform);
  const run = options.run ?? ((command: string) => spawnSync(command, { stdio: 'inherit', shell: true }));

  const directory = await mkdtemp(join(tmpdir(), 'codeguard-edit-'));
  const file = join(directory, 'patch.diff');

  try {
    await writeFile(file, patch, { encoding: 'utf8', mode: 0o600 });
    const result = run(`${editor} "${file}"`);

    let edited: string;
    try {
      edited = await readFile(file, 'utf8');
    } catch (error) {
      return { ok: false, reason: `could not read back the edited patch — ${message(error)}` };
    }

    if (edited.trim() === '') {
      // An empty file is how a person aborts an editor-driven step, and treating
      // it as "apply nothing" would silently skip a finding.
      return { ok: false, reason: 'the patch was left empty, so the edit was abandoned' };
    }

    if (edited === patch) {
      return { ok: false, reason: 'the patch was saved unchanged' };
    }

    return { ok: true, text: edited };
  } finally {
    // The patch is a copy of the developer's own code, but leaving copies of
    // source in the temp directory after every edit is not a habit worth having.
    await rm(directory, { recursive: true, force: true });
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
