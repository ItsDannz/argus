/**
 * Repairing a model-written patch (FR-6, FR-7).
 *
 * The first test in this file is the defect, written as the live provider
 * produced it: hunk headers whose counts disagree with their bodies, and no file
 * header. Everything after it is a boundary — what the repair will derive, and
 * what it refuses to guess.
 */

import { describe, expect, it } from '@jest/globals';

import { fixtureLines, readFixture } from '../../engine/local/__tests__/helpers';
import { applyToText } from '../apply';
import { parseAndRepairPatch, validatePatch } from '../normalise';

const FILE = 'server/routes/users.js';

/** Body of a hunk, as lines of a patch string. */
function patch(...lines: string[]): string {
  return lines.join('\n');
}

describe('parseAndRepairPatch — the observed defect', () => {
  it('recounts a hunk whose header overstates the new side', () => {
    // Exactly the shape a live scan returned: two removed lines and ONE added
    // line under a header claiming two of each. The old-side count is right and
    // the new-side count is not, which is what the live sample showed.
    // `parsePatch` rejects the whole patch over this, so the applier never even
    // gets to try — the developer sees a finding with no way to fix it.
    const raw = patch(
      '@@ -11,2 +11,2 @@',
      '-  const sql = "SELECT id, email FROM users WHERE id = " + userId;',
      '-  db.query(sql, (err, rows) => res.json(rows));',
      '+  const sql = "SELECT id, email FROM users WHERE id = ?";',
    );

    const result = parseAndRepairPatch(raw, FILE);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.patch.text).toContain('@@ -11,2 +11,1 @@');
    expect(result.patch.repairs).toContainEqual(expect.stringContaining('hunk 1'));
    // The declared range follows the repair, because the placement check
    // compares against the range the applier will actually use.
    expect(result.patch.hunks).toEqual([{ oldStart: 11, oldLines: 2, newStart: 11, newLines: 1 }]);
  });

  it('adds the file header the model left off', () => {
    const raw = patch('@@ -1,1 +1,1 @@', '-a', '+b');

    const result = parseAndRepairPatch(raw, FILE);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.patch.text.split('\n').slice(0, 2)).toEqual([
      `--- a/${FILE}`,
      `+++ b/${FILE}`,
    ]);
    expect(result.patch.repairs).toContainEqual(expect.stringContaining('added the missing file header'));
  });

  it('leaves a well-formed patch alone apart from the header', () => {
    // The repair is not allowed to be the thing that breaks a patch that was
    // already correct.
    const raw = patch(
      '--- a/other.js',
      '+++ b/other.js',
      '@@ -3,3 +3,3 @@',
      ' keep',
      '-old',
      '+new',
      ' keep',
    );

    const result = parseAndRepairPatch(raw, FILE);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.patch.text).toBe(
      [`--- a/${FILE}`, `+++ b/${FILE}`, '@@ -3,3 +3,3 @@', ' keep', '-old', '+new', ' keep', ''].join('\n'),
    );
    // Only the retargeting is reported; the hunk itself needed nothing.
    expect(result.patch.repairs).toHaveLength(1);
    expect(result.patch.repairs[0]).toContain('replaced the patch');
  });

  it('treats an empty line inside a hunk as an empty context line', () => {
    // A context line that is empty is a single space. Models drop it, and the
    // header counts then disagree with the body in a way that looks like a count
    // bug rather than a formatting one.
    //
    // The counts move from 2/2 to 3/3 as a result, which is the repair being
    // consistent rather than the repair being wrong: the header described a body
    // with no blank context line, and the body has one.
    const raw = patch('@@ -1,2 +1,2 @@', ' first', '', '-old', '+new');

    const result = parseAndRepairPatch(raw, FILE);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.patch.text).toContain('@@ -1,3 +1,3 @@');
    // The blank line is now a marked context line, not an unmarked blank.
    expect(result.patch.text.split('\n')).toContain(' ');
    expect(result.patch.repairs).toContainEqual(expect.stringContaining('hunk 1'));
  });

  it('counts each hunk of a multi-hunk patch independently', () => {
    const raw = patch(
      '@@ -1,1 +1,1 @@',
      '-a',
      '+b',
      '@@ -20,3 +20,2 @@',
      ' keep',
      '-old',
      '+new',
    );

    const result = parseAndRepairPatch(raw, FILE);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.patch.hunks).toEqual([
      { oldStart: 1, oldLines: 1, newStart: 1, newLines: 1 },
      { oldStart: 20, oldLines: 2, newStart: 20, newLines: 2 },
    ]);
    // Only the second hunk's header was wrong.
    expect(result.patch.repairs.filter((entry) => entry.startsWith('hunk '))).toHaveLength(1);
  });

  it('carries the no-newline marker through without counting it', () => {
    const raw = patch('@@ -1,1 +1,1 @@', '-a', '+b', '\\ No newline at end of file');

    const result = parseAndRepairPatch(raw, FILE);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.patch.hunks).toEqual([{ oldStart: 1, oldLines: 1, newStart: 1, newLines: 1 }]);
    expect(result.patch.text).toContain('\\ No newline at end of file');
  });

  it('keeps the provider text verbatim alongside the repaired form', () => {
    // What the model actually said is evidence — for the [v]iew option, for a
    // bug report, and for judging whether the repair changed the meaning.
    const raw = patch('@@ -1,2 +1,2 @@', '-a', '+b');

    const result = parseAndRepairPatch(raw, FILE);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.patch.original).toBe(raw);
  });
});

describe('parseAndRepairPatch — what it refuses to guess', () => {
  it('refuses a body line that is not a diff line, and says which', () => {
    // The classic: the model elides unchanged code. Applying that would delete
    // or duplicate whatever it skipped, so it is refused rather than guessed.
    const raw = patch('@@ -1,4 +1,4 @@', ' keep', '-old', '+new', '...');

    const result = parseAndRepairPatch(raw, FILE);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    // Line 5 of the patch as written: the header is line 1.
    expect(result.reason).toContain('line 5');
    expect(result.reason).toContain('...');
  });

  it('counts the line number from the top of the patch, header included', () => {
    // With a header present, the body starts two lines in. An error saying
    // "line 4" has to mean line 4 of the text the developer can look at.
    const raw = patch(
      '--- a/other.js',
      '+++ b/other.js',
      '@@ -1,2 +1,2 @@',
      ' keep',
      '???',
    );

    const result = parseAndRepairPatch(raw, FILE);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain('line 5');
  });

  it('refuses a patch with no hunk header at all', () => {
    const result = parseAndRepairPatch('I could not produce a patch for this change.', FILE);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain('no hunk header');
  });

  it('refuses a hunk that claims to be empty', () => {
    const result = parseAndRepairPatch(patch('@@ -1,1 +1,1 @@'), FILE);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toContain('no content lines');
  });
});

describe('validatePatch', () => {
  it('accepts what the repair produces', () => {
    const raw = patch('@@ -11,2 +11,2 @@', ' ctx', '-old', '+new');
    const result = parseAndRepairPatch(raw, FILE);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(validatePatch(result.patch.text)).toEqual({ ok: true });
  });

  it('rejects an empty patch and a multi-file one', () => {
    // The [e]dit flow runs human-typed text through this, so it has to reject
    // the shapes a human can produce as well as the ones a model does.
    expect(validatePatch('   ')).toEqual({ ok: false, reason: 'the patch is empty' });

    const twoFiles = [
      '--- a/one.js',
      '+++ b/one.js',
      '@@ -1,1 +1,1 @@',
      '-a',
      '+b',
      '--- a/two.js',
      '+++ b/two.js',
      '@@ -1,1 +1,1 @@',
      '-c',
      '+d',
      '',
    ].join('\n');
    const checked = validatePatch(twoFiles);
    expect(checked.ok).toBe(false);
    if (checked.ok) return;
    expect(checked.reason).toContain('2 files');
  });
});

describe('the repaired patch still does what the model intended', () => {
  it('applies to the real fixture and parameterises the query', () => {
    // The end-to-end point of the whole module: the defect's own shape, fixed,
    // against the file the finding was about.
    const source = readFixture('sql-injection.js');
    const raw = patch(
      '@@ -9,5 +9,5 @@',
      " router.get('/user', (req, res) => {",
      '   const userId = req.query.id;',
      '-  const sql = "SELECT id, email FROM users WHERE id = " + userId;',
      '-  db.query(sql, (err, rows) => res.json(rows));',
      '+  const sql = "SELECT id, email FROM users WHERE id = ?";',
      '+  db.query(sql, [userId], (err, rows) => res.json(rows));',
      ' });',
    );

    const result = parseAndRepairPatch(raw, FILE);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const applied = applyToText(fixtureLines(source).join('\n') + '\n', result.patch);
    expect(applied.ok).toBe(true);
    if (!applied.ok) return;

    expect(applied.content).toContain('db.query(sql, [userId], (err, rows) => res.json(rows));');
    expect(applied.content).not.toContain('WHERE id = " + userId');
    // Nothing else in the file moved.
    expect(applied.content.split('\n')).toHaveLength(fixtureLines(source).length + 1);
  });
});
