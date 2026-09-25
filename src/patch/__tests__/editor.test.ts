/**
 * Handing a patch to $EDITOR (FR-7's Edit branch).
 *
 * The one part of Phase 5 that cannot be checked by reading its output, because
 * its whole job is to hand the terminal to another process and read a file
 * back. So the `run` seam is injected and the editor is simulated by writing to
 * the path it was handed — which keeps the real temp-file, real read-back and
 * real cleanup path under test, and only skips the actual editor.
 */

import { existsSync, rmSync, writeFileSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, describe, expect, it } from '@jest/globals';

import { editInEditor, resolveEditor } from '../editor';

const cleanup: string[] = [];

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

/**
 * The path the command was told to open.
 *
 * Extracted from the shell line rather than passed around, so the test sees
 * exactly what the editor would have seen — a test that received the path
 * another way could pass while the command was malformed.
 */
function pathIn(command: string): string {
  const match = /^(.+?) "(.+)"$/.exec(command);
  if (match === null) throw new Error(`the command is not "editor \"path\"": ${command}`);
  return match[2] ?? '';
}

describe('resolveEditor', () => {
  it('prefers VISUAL over EDITOR, as Git does', () => {
    expect(resolveEditor({ VISUAL: 'code --wait', EDITOR: 'vi' }, 'linux')).toBe('code --wait');
  });

  it('falls back to EDITOR when VISUAL is unset or empty', () => {
    expect(resolveEditor({ EDITOR: 'nano' }, 'linux')).toBe('nano');
    expect(resolveEditor({ VISUAL: '', EDITOR: 'nano' }, 'linux')).toBe('nano');
    expect(resolveEditor({ VISUAL: '   ', EDITOR: 'nano' }, 'linux')).toBe('nano');
  });

  it('uses notepad on Windows and vi elsewhere', () => {
    expect(resolveEditor({}, 'win32')).toBe('notepad');
    expect(resolveEditor({}, 'linux')).toBe('vi');
    expect(resolveEditor({}, 'darwin')).toBe('vi');
  });
});

describe('editInEditor', () => {
  it('hands the editor one shell line, with the patch path quoted', async () => {
    const commands: string[] = [];
    const outcome = await editInEditor('# the patch\n', {
      env: { EDITOR: 'code --wait' },
      platform: 'linux',
      run: (command) => {
        commands.push(command);
        return { status: 0 };
      },
    });

    expect(commands).toHaveLength(1);
    expect(commands[0]).toMatch(/^code --wait ".+"$/);
    // Saved unchanged, so the edit is refused — but the command shape above is
    // the point: `EDITOR="code --wait"` must survive as two words plus a path.
    expect(outcome.ok).toBe(false);
  });

  it('returns what the developer saved', async () => {
    const outcome = await editInEditor('original\n', {
      env: { EDITOR: 'ed' },
      platform: 'linux',
      run: (command) => {
        writeFileSync(pathIn(command), 'edited by a human\n', 'utf8');
        return { status: 0 };
      },
    });

    expect(outcome).toEqual({ ok: true, text: 'edited by a human\n' });
  });

  it('refuses an unchanged save, rather than applying the model`s patch by accident', async () => {
    // The developer opened the editor and exited without changing anything.
    // Treating that as "accept" would turn [e]dit into a slower [a]pply.
    const outcome = await editInEditor('original\n', {
      env: { EDITOR: 'ed' },
      platform: 'linux',
      run: () => ({ status: 0 }),
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.ok ? '' : outcome.reason).toContain('saved unchanged');
  });

  it('treats an emptied file as abandoned, not as "apply nothing"', async () => {
    const outcome = await editInEditor('original\n', {
      env: { EDITOR: 'ed' },
      platform: 'linux',
      run: (command) => {
        writeFileSync(pathIn(command), '\n  \n', 'utf8');
        return { status: 0 };
      },
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.ok ? '' : outcome.reason).toContain('left empty');
  });

  it('reports a read-back failure instead of throwing', async () => {
    const outcome = await editInEditor('original\n', {
      env: { EDITOR: 'ed' },
      platform: 'linux',
      run: (command) => {
        rmSync(pathIn(command), { force: true });
        return { status: 0 };
      },
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.ok ? '' : outcome.reason).toContain('could not read back the edited patch');
  });

  it('removes the temporary file afterwards, whatever the editor did', async () => {
    let seen = '';
    await editInEditor('original\n', {
      env: { EDITOR: 'ed' },
      platform: 'linux',
      run: (command) => {
        seen = pathIn(command);
        return { status: 1 };
      },
    });

    // A copy of the developer's source should not outlive the edit.
    expect(existsSync(seen)).toBe(false);
    expect(existsSync(path.dirname(seen))).toBe(false);
  });

  it('writes the patch into the temp directory, not into the repository', async () => {
    let seen = '';
    await editInEditor('original\n', {
      env: { EDITOR: 'ed' },
      platform: 'linux',
      run: (command) => {
        seen = pathIn(command);
        return { status: 0 };
      },
    });

    const resolved = path.resolve(seen);
    expect(resolved.startsWith(path.resolve(tmpdir()) + path.sep)).toBe(true);
    expect(path.basename(path.dirname(resolved))).toMatch(/^codeguard-edit-/);
    // Phase 5 depends on this: a patch file written inside the working tree
    // would be `git add`-able, and the developer would be committing the diff
    // they were asked to review.
    expect(resolved.startsWith(path.resolve(process.cwd()) + path.sep)).toBe(false);
  });
});
