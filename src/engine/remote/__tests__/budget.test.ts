/**
 * Preparing a diff for transmission.
 *
 * The property under test throughout is all-or-nothing: a file section is either
 * sent whole or not at all, and every file that is not sent is named in the
 * result. A diff truncated mid-hunk would not merely look wrong — the model's
 * line numbers are mapped back to hunks, so a broken hunk would silently place
 * findings on the wrong lines.
 */

import { describe, expect, it } from '@jest/globals';

import { filterExcludedFiles, MAX_TRIAGE_CHARS, splitSections, truncateToBudget } from '../budget';

/** A minimal file section. */
function section(path: string, added: number): string[] {
  return [
    `diff --git a/${path} b/${path}`,
    'new file mode 100644',
    'index 0000000..1111111',
    '--- /dev/null',
    `+++ b/${path}`,
    `@@ -0,0 +1,${added} @@`,
    ...Array.from({ length: added }, (_, i) => `+line ${i + 1} of ${path}`),
  ];
}

const ONE = section('src/one.js', 2);
const TWO = section('src/two.js', 2);
const THREE = section('src/three.js', 2);
const ALL = [...ONE, ...TWO, ...THREE].join('\n');

describe('splitSections', () => {
  it('splits one section per file, in diff order', () => {
    const sections = splitSections(ALL);

    expect(sections.map((s) => s.path)).toEqual(['src/one.js', 'src/two.js', 'src/three.js']);
    expect(sections.every((s) => s.isFile)).toBe(true);
  });

  it('reads the path from the +++ line, not the header', () => {
    // A rename has a different path on each side; the new side is the one the
    // model is asked about and the one findings are anchored to.
    const rename = [
      'diff --git a/old/name.js b/new/name.js',
      'similarity index 90%',
      'rename from old/name.js',
      'rename to new/name.js',
      '--- a/old/name.js',
      '+++ b/new/name.js',
      '@@ -1,1 +1,1 @@',
      '-old',
      '+new',
    ].join('\n');

    expect(splitSections(rename)[0]?.path).toBe('new/name.js');
  });

  it('reassembles the input exactly', () => {
    // The sections are the unit of deletion, so any byte lost between them would
    // be a byte silently dropped from what the model sees.
    expect(
      splitSections(ALL)
        .map((s) => s.text)
        .join('\n'),
    ).toBe(ALL);
  });

  it('keeps a preamble as a non-file section rather than discarding it', () => {
    const withPreamble = `warning: something happened\n${ALL}`;
    const sections = splitSections(withPreamble);

    expect(sections).toHaveLength(4);
    expect(sections[0]?.isFile).toBe(false);
    expect(sections[0]?.text).toContain('warning: something happened');
  });

  it('falls back to the header path for a binary file, which has no +++ line', () => {
    const binary = [
      'diff --git a/assets/logo.png b/assets/logo.png',
      'new file mode 100644',
      'index 0000000..2222222',
      'Binary files /dev/null and b/assets/logo.png differ',
    ].join('\n');

    const sections = splitSections(binary);
    expect(sections[0]?.path).toBe('assets/logo.png');
    expect(sections[0]?.isFile).toBe(true);
  });
});

describe('filterExcludedFiles', () => {
  it('removes a whole section and reports what it removed', () => {
    const result = filterExcludedFiles(ALL, (path) => path === 'src/two.js');

    expect(result.diff).not.toContain('src/two.js');
    expect(result.diff).toContain('src/one.js');
    expect(result.diff).toContain('src/three.js');
    // Reported, so an exclusion is never invisible to the developer.
    expect(result.excluded).toEqual(['src/two.js']);
  });

  it('keeps everything when nothing matches', () => {
    const result = filterExcludedFiles(ALL, () => false);

    expect(result.diff).toBe(ALL);
    expect(result.excluded).toEqual([]);
  });

  it('passes the repo-relative path, without the a/ or b/ prefix', () => {
    const seen: string[] = [];
    filterExcludedFiles(ALL, (path) => {
      seen.push(path);
      return false;
    });

    expect(seen).toEqual(['src/one.js', 'src/two.js', 'src/three.js']);
  });

  it('removes every file when the predicate matches all of them', () => {
    const result = filterExcludedFiles(ALL, () => true);

    expect(result.diff).toBe('');
    expect(result.excluded).toHaveLength(3);
  });

  it('never leaves a partial section behind', () => {
    // The all-or-nothing property. A half-removed file would still contain the
    // `@@` header, and the model's line numbers would then be matched against a
    // hunk whose body is gone.
    const result = filterExcludedFiles(ALL, (path) => path === 'src/one.js');

    expect(result.diff.startsWith('diff --git a/src/two.js')).toBe(true);
    expect(result.diff).not.toContain('@0,0 +1,2 @@');
  });
});

describe('truncateToBudget', () => {
  it('returns the diff untouched when it fits', () => {
    const result = truncateToBudget(ALL);

    expect(result.diff).toBe(ALL);
    expect(result.omitted).toEqual([]);
    expect(result.empty).toBe(false);
  });

  it('drops trailing whole files and names every one it dropped', () => {
    // Sized so exactly one file fits. The dropped files are named in full, not
    // counted: the report has to say WHICH files went unexamined, or a partial
    // scan reads as a complete one.
    const result = truncateToBudget(ALL, ONE.join('\n').length + 1);

    expect(result.diff).toBe(ONE.join('\n'));
    expect(result.omitted).toEqual(['src/two.js', 'src/three.js']);
    expect(result.empty).toBe(false);
  });

  it('keeps the first file even when it alone busts the budget', () => {
    // Sending one oversized file is strictly more useful than sending nothing,
    // and the alternative is reporting a scan that never happened.
    const result = truncateToBudget(ALL, 10);

    expect(result.diff).toBe(ONE.join('\n'));
    expect(result.omitted).toHaveLength(2);
    expect(result.empty).toBe(false);
  });

  it('reports an empty diff as empty, and sends nothing', () => {
    // Without this, the pipeline would make an API call about an empty prompt —
    // a wasted request, and an open invitation for the model to invent findings.
    const result = truncateToBudget('');

    expect(result.empty).toBe(true);
    expect(result.diff).toBe('');
  });

  it('reports a diff with no file sections as empty', () => {
    const result = truncateToBudget('warning: nothing here\n');

    expect(result.empty).toBe(true);
    expect(result.diff).toBe('');
  });

  it('reports a diff whose files were all excluded as empty', () => {
    // The excluded-then-truncated order means an all-excluded diff arrives here
    // as '', and this is the check that stops a pointless request.
    const filtered = filterExcludedFiles(ALL, () => true);
    const result = truncateToBudget(filtered.diff);

    expect(result.empty).toBe(true);
  });

  it('has a budget large enough to hold an ordinary commit', () => {
    // A guard on the guard: if MAX_TRIAGE_CHARS were ever lowered to something
    // small, ordinary commits would start silently losing files.
    expect(MAX_TRIAGE_CHARS).toBeGreaterThanOrEqual(100_000);
  });
});
