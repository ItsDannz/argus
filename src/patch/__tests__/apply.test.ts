/**
 * Writing a patch into the working tree (FR-7).
 *
 * The happy path is one test. The rest are the cases where the applier would
 * otherwise write something wrong: a patch that does not fit, a patch that
 * changes nothing, a patch that fits somewhere other than where it says it
 * belongs, a file whose line endings would be rewritten wholesale, and a path
 * that points out of the repository.
 */

import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { beforeEach, describe, expect, it } from '@jest/globals';

import { applyPatchToFile, applyToText } from '../apply';
import { parseAndRepairPatch, type RepairedPatch } from '../normalise';

const FILE = 'src/db.js';

/** A patch parsed through the repair, so tests exercise the real path. */
function repaired(raw: string, file = FILE): RepairedPatch {
  const result = parseAndRepairPatch(raw, file);
  if (!result.ok) throw new Error(`fixture patch did not parse: ${result.reason}`);
  return result.patch;
}

describe('applyToText — what it refuses', () => {
  it('refuses a patch that does not fit the file', () => {
    const patch = repaired(['@@ -1,3 +1,3 @@', ' keep', '-old', '+new', ' keep'].join('\n'));

    const result = applyToText('nothing\nlike\nthis\n', patch);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain('does not fit');
  });

  it('refuses a patch that applies but changes nothing', () => {
    // A context-only hunk. There is no such thing as a suggested patch that
    // changes nothing, so applying one would stage a change called "fixed" that
    // fixes nothing.
    const patch = repaired(['@@ -1,2 +1,2 @@', ' keep', ' second'].join('\n'));

    const result = applyToText('keep\nsecond\n', patch);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain('changed nothing');
  });

  it('refuses an edit that lands outside the range the hunk declares', () => {
    // The failure the placement check exists for. `applyPatch` anchors on
    // content, not line numbers, and scans outwards when the declared position
    // does not match — so a file with a repeated block can satisfy the wrong
    // copy and produce a real edit in the wrong place.
    //
    // Here the hunk says line 3 and its content lives at 10-12.
    const source = ['L1', 'L2', 'X1', 'X2', 'X3', 'L6', 'L7', 'L8', 'L9', 'A', 'B', 'C', ''].join(
      '\n',
    );
    const patch = repaired(['@@ -3,3 +3,3 @@', ' A', '-B', '+B2', ' C'].join('\n'));

    const result = applyToText(source, patch);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain('line 11');
    expect(result.reason).toContain('outside every range');
  });

  it('allows an edit placed where the hunk says it belongs', () => {
    // The same shape as the test above, with the declared position corrected.
    // One line of slack at each end of the range is deliberate, for removals —
    // so this also pins that the slack does not extend to a different block.
    const source = ['L1', 'L2', 'A', 'B', 'C', 'L6', 'L7', 'L8', 'L9', 'A', 'B', 'C', ''].join('\n');
    const patch = repaired(['@@ -3,3 +3,3 @@', ' A', '-B', '+B2', ' C'].join('\n'));

    const result = applyToText(source, patch);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // The FIRST copy, which is the one the hunk named.
    expect(result.content.split('\n').slice(0, 6).join('\n')).toBe('L1\nL2\nA\nB2\nC\nL6');
    expect(result.content.split('\n').slice(9, 12).join('\n')).toBe('A\nB\nC');
    expect(result.changedLines).toEqual([4]);
  });
});

describe('applyPatchToFile', () => {
  let repoRoot: string;

  beforeEach(async () => {
    repoRoot = await mkdtemp(join(tmpdir(), 'codeguard-patch-'));
  });

  it('writes the file and reports which lines changed', async () => {
    await writeFile(join(repoRoot, 'db.js'), 'keep\nold\nkeep\n', 'utf8');
    const patch = repaired(['@@ -1,3 +1,3 @@', ' keep', '-old', '+new', ' keep'].join('\n'), 'db.js');

    const result = await applyPatchToFile({ repoRoot, file: 'db.js', patch });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(await readFile(join(repoRoot, 'db.js'), 'utf8')).toBe('keep\nnew\nkeep\n');
    expect(result.changedLines).toEqual([2]);
  });

  it('keeps CRLF line endings on a CRLF file', async () => {
    // Rewriting a Windows checkout in LF would turn a one-line fix into a
    // whole-file diff, which is the kind of noise that gets a tool switched off.
    await writeFile(join(repoRoot, 'db.js'), 'keep\r\nold\r\nkeep\r\n', 'utf8');
    const patch = repaired(['@@ -1,3 +1,3 @@', ' keep', '-old', '+new', ' keep'].join('\n'), 'db.js');

    const result = await applyPatchToFile({ repoRoot, file: 'db.js', patch });

    expect(result.ok).toBe(true);
    expect(await readFile(join(repoRoot, 'db.js'), 'utf8')).toBe('keep\r\nnew\r\nkeep\r\n');
  });

  it('refuses a file with mixed line endings', async () => {
    await writeFile(join(repoRoot, 'db.js'), 'keep\r\nold\nkeep\r\n', 'utf8');
    const patch = repaired(['@@ -1,3 +1,3 @@', ' keep', '-old', '+new', ' keep'].join('\n'), 'db.js');

    const result = await applyPatchToFile({ repoRoot, file: 'db.js', patch });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain('mixes LF and CRLF');
    // Untouched — a refusal that still wrote would be the worst outcome.
    expect(await readFile(join(repoRoot, 'db.js'), 'utf8')).toBe('keep\r\nold\nkeep\r\n');
  });

  it('refuses a path that leaves the repository', async () => {
    // The file name reaches this layer from a finding, and the finding came
    // from a parsed diff — but this is the write path, so the check is cheap and
    // the thing it prevents is not.
    const patch = repaired(['@@ -1,1 +1,1 @@', '-a', '+b'].join('\n'), '../outside.js');

    const result = await applyPatchToFile({ repoRoot, file: '../outside.js', patch });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain('outside the repository');
  });

  it('refuses a file that is not there', async () => {
    const patch = repaired(['@@ -1,1 +1,1 @@', '-a', '+b'].join('\n'), 'gone.js');

    const result = await applyPatchToFile({ repoRoot, file: 'gone.js', patch });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain('does not exist');
  });
});
