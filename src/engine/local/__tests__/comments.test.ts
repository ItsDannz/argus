import { describe, expect, it } from '@jest/globals';

import { commentPrefixesFor, fileExtension, isWholeLineComment } from '../source-file';

describe('fileExtension', () => {
  it('returns a lower-cased extension', () => {
    expect(fileExtension('src/App.TS')).toBe('.ts');
    expect(fileExtension('a/b/c.py')).toBe('.py');
  });

  it('returns an empty string when there is no extension', () => {
    expect(fileExtension('Makefile')).toBe('');
    expect(fileExtension('deploy/Dockerfile')).toBe('');
  });

  it('ignores a dot that belongs to a directory name, not the file', () => {
    // "my.folder/Makefile" must not be read as a ".folder/Makefile" extension.
    expect(fileExtension('my.folder/Makefile')).toBe('');
    expect(fileExtension('my.folder/app.ts')).toBe('.ts');
  });
});

describe('commentPrefixesFor', () => {
  it('gives C and C++ only "//", never "#"', () => {
    expect(commentPrefixesFor('a.c')).toEqual(['//']);
    expect(commentPrefixesFor('a.cpp')).toEqual(['//']);
    expect(commentPrefixesFor('a.h')).toEqual(['//']);
    expect(commentPrefixesFor('a.hpp')).toEqual(['//']);
  });

  it('gives the hash-comment languages "#"', () => {
    expect(commentPrefixesFor('a.py')).toEqual(['#']);
    expect(commentPrefixesFor('a.sh')).toEqual(['#']);
    expect(commentPrefixesFor('a.rb')).toEqual(['#']);
  });

  it('gives PHP both, and an unknown type nothing at all', () => {
    expect(commentPrefixesFor('a.php')).toEqual(['//', '#']);
    expect(commentPrefixesFor('notes.md')).toEqual([]);
    expect(commentPrefixesFor('Makefile')).toEqual([]);
  });
});

describe('isWholeLineComment', () => {
  it('recognises a comment at the start of a line', () => {
    expect(isWholeLineComment('a.c', '// strcpy(x, y);')).toBe(true);
    expect(isWholeLineComment('a.py', '# md5(pw)')).toBe(true);
  });

  it('recognises a comment after leading whitespace', () => {
    expect(isWholeLineComment('a.c', '      // indented comment')).toBe(true);
    expect(isWholeLineComment('a.py', '\t# tab indented')).toBe(true);
  });

  it('is false for code, including code sharing a line with a marker', () => {
    expect(isWholeLineComment('a.c', 'strcpy(x, y); // trailing')).toBe(false);
    expect(isWholeLineComment('a.py', 'x = 1  # trailing')).toBe(false);
    expect(isWholeLineComment('a.c', 'a / b // c')).toBe(false);
  });

  it('is false for a blank or whitespace-only line', () => {
    expect(isWholeLineComment('a.c', '')).toBe(false);
    expect(isWholeLineComment('a.c', '   ')).toBe(false);
  });

  it('is false when the file type is unknown, so nothing is silently skipped', () => {
    expect(isWholeLineComment('notes.txt', '// strcpy(x, y);')).toBe(false);
    expect(isWholeLineComment('biome.json', '# md5(pw)')).toBe(false);
  });

  it('does not treat "#" as a comment in C', () => {
    expect(isWholeLineComment('a.c', '#define X 1')).toBe(false);
    expect(isWholeLineComment('a.cpp', '#include <string.h>')).toBe(false);
  });
});
