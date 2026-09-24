import { describe, expect, it } from '@jest/globals';

import { addedLines, parseDiff } from '../../diff';

describe('parseDiff', () => {
  it('returns no files for empty or unrecognised input', () => {
    expect(parseDiff('')).toEqual([]);
    expect(parseDiff('this is not a diff\njust some prose')).toEqual([]);
  });

  it('parses an added file and numbers its lines from 1', () => {
    const diff = [
      'diff --git a/src/app.js b/src/app.js',
      'new file mode 100644',
      'index 0000000..1234567',
      '--- /dev/null',
      '+++ b/src/app.js',
      '@@ -0,0 +1,3 @@',
      '+first',
      '+second',
      '+third',
      '',
    ].join('\n');

    const files = parseDiff(diff);
    expect(files).toHaveLength(1);

    const file = files[0]!;
    expect(file.path).toBe('src/app.js');
    expect(file.status).toBe('added');
    expect(file.previousPath).toBeNull();
    expect(file.isBinary).toBe(false);
    expect(file.hunks).toHaveLength(1);

    const hunk = file.hunks[0]!;
    expect(hunk.newStart).toBe(1);
    expect(hunk.newCount).toBe(3);
    expect(hunk.lines.map((line) => line.newLine)).toEqual([1, 2, 3]);
    expect(hunk.lines.map((line) => line.content)).toEqual(['first', 'second', 'third']);
    // Added lines exist only in the new file.
    expect(hunk.lines.every((line) => line.oldLine === null)).toBe(true);
    expect(hunk.lines.every((line) => line.kind === 'add')).toBe(true);
  });

  it('tracks old and new line numbers independently across context, deletion, and addition', () => {
    // This is the test that pins the counter discipline down. A naively written
    // parser that advances a single shared counter gets `const d = 4` wrong.
    const diff = [
      'diff --git a/app.js b/app.js',
      'index 1111111..2222222 100644',
      '--- a/app.js',
      '+++ b/app.js',
      '@@ -10,4 +10,5 @@ function main() {',
      ' const a = 1;',
      '-const b = 2;',
      '+const b = 22;',
      '+const c = 3;',
      ' const d = 4;',
      '',
    ].join('\n');

    const hunk = parseDiff(diff)[0]!.hunks[0]!;
    expect(hunk.lines).toEqual([
      { kind: 'context', content: 'const a = 1;', oldLine: 10, newLine: 10 },
      { kind: 'del', content: 'const b = 2;', oldLine: 11, newLine: null },
      { kind: 'add', content: 'const b = 22;', oldLine: null, newLine: 11 },
      { kind: 'add', content: 'const c = 3;', oldLine: null, newLine: 12 },
      { kind: 'context', content: 'const d = 4;', oldLine: 12, newLine: 13 },
    ]);
  });

  it('restarts line counters for each hunk', () => {
    const diff = [
      'diff --git a/app.js b/app.js',
      'index 1111111..2222222 100644',
      '--- a/app.js',
      '+++ b/app.js',
      '@@ -1,2 +1,2 @@',
      '-a',
      '+b',
      '@@ -50,2 +50,3 @@',
      ' x',
      '+y',
      '+z',
      '',
    ].join('\n');

    const file = parseDiff(diff)[0]!;
    expect(file.hunks).toHaveLength(2);

    const second = file.hunks[1]!;
    expect(second.newStart).toBe(50);
    expect(second.lines.map((line) => line.newLine)).toEqual([50, 51, 52]);
  });

  it('parses multiple files in one diff', () => {
    const diff = [
      'diff --git a/one.js b/one.js',
      'index 1111111..2222222 100644',
      '--- a/one.js',
      '+++ b/one.js',
      '@@ -1,1 +1,1 @@',
      '-old one',
      '+new one',
      'diff --git a/two.js b/two.js',
      'index 3333333..4444444 100644',
      '--- a/two.js',
      '+++ b/two.js',
      '@@ -1,1 +1,1 @@',
      '-old two',
      '+new two',
      '',
    ].join('\n');

    const files = parseDiff(diff);
    expect(files.map((file) => file.path)).toEqual(['one.js', 'two.js']);
    expect(files.map((file) => file.status)).toEqual(['modified', 'modified']);
  });

  it('reports a deleted file under its old path', () => {
    const diff = [
      'diff --git a/gone.js b/gone.js',
      'deleted file mode 100644',
      'index 1111111..0000000',
      '--- a/gone.js',
      '+++ /dev/null',
      '@@ -1,2 +0,0 @@',
      '-line one',
      '-line two',
      '',
    ].join('\n');

    const file = parseDiff(diff)[0]!;
    expect(file.status).toBe('deleted');
    expect(file.path).toBe('gone.js');
    expect(file.hunks[0]!.lines.every((line) => line.kind === 'del')).toBe(true);
  });

  it('classifies a pure rename, which carries no --- or +++ lines', () => {
    // Git emits only rename metadata when content is unchanged. Status must
    // still be resolved, which is why it is decided after the file is complete.
    const diff = [
      'diff --git a/old.js b/new.js',
      'similarity index 100%',
      'rename from old.js',
      'rename to new.js',
      '',
    ].join('\n');

    const file = parseDiff(diff)[0]!;
    expect(file.status).toBe('renamed');
    expect(file.path).toBe('new.js');
    expect(file.previousPath).toBe('old.js');
  });

  it('parses a CRLF diff identically to an LF one', () => {
    // Windows checkouts can produce CRLF; a stray \r would otherwise end up
    // inside every matched line and silently break the rules.
    const lf = [
      'diff --git a/app.js b/app.js',
      'index 1111111..2222222 100644',
      '--- a/app.js',
      '+++ b/app.js',
      '@@ -1,1 +1,1 @@',
      '-old',
      '+new',
      '',
    ].join('\n');

    const fromLf = parseDiff(lf)[0]!;
    const fromCrlf = parseDiff(lf.replace(/\n/g, '\r\n'))[0]!;

    expect(fromCrlf.path).toBe(fromLf.path);
    expect(fromCrlf.hunks[0]!.lines).toEqual(fromLf.hunks[0]!.lines);
    // lines[0] is the deletion; lines[1] is the addition.
    expect(fromCrlf.hunks[0]!.lines[1]!.content).toBe('new');
  });

  it('unquotes paths containing spaces', () => {
    const diff = [
      'diff --git "a/my file.js" "b/my file.js"',
      'index 1111111..2222222 100644',
      '--- "a/my file.js"',
      '+++ "b/my file.js"',
      '@@ -1,1 +1,1 @@',
      '-a',
      '+b',
      '',
    ].join('\n');

    expect(parseDiff(diff)[0]!.path).toBe('my file.js');
  });

  it('flags binary files and recovers their path without --- or +++ lines', () => {
    const diff = [
      'diff --git a/assets/logo.png b/assets/logo.png',
      'index 1111111..2222222 100644',
      'Binary files a/assets/logo.png and b/assets/logo.png differ',
      '',
    ].join('\n');

    const file = parseDiff(diff)[0]!;
    expect(file.isBinary).toBe(true);
    expect(file.path).toBe('assets/logo.png');
    expect(file.hunks).toEqual([]);
  });

  it('does not treat the no-newline marker as a line of its own', () => {
    const diff = [
      'diff --git a/app.js b/app.js',
      'index 1111111..2222222 100644',
      '--- a/app.js',
      '+++ b/app.js',
      '@@ -1,1 +1,1 @@',
      '-old',
      '+new',
      '\\ No newline at end of file',
      '',
    ].join('\n');

    const hunk = parseDiff(diff)[0]!.hunks[0]!;
    expect(hunk.lines).toHaveLength(2);
    expect(hunk.lines[1]).toEqual({ kind: 'add', content: 'new', oldLine: null, newLine: 1 });
  });
});

describe('addedLines', () => {
  it('returns only added lines, across every hunk', () => {
    const diff = [
      'diff --git a/app.js b/app.js',
      'index 1111111..2222222 100644',
      '--- a/app.js',
      '+++ b/app.js',
      '@@ -1,3 +1,4 @@',
      ' keep',
      '-drop',
      '+added one',
      ' keep two',
      '@@ -20,1 +21,2 @@',
      ' context',
      '+added two',
      '',
    ].join('\n');

    const file = parseDiff(diff)[0]!;
    expect(addedLines(file).map((line) => line.content)).toEqual(['added one', 'added two']);
    expect(addedLines(file).map((line) => line.newLine)).toEqual([2, 22]);
  });
});
