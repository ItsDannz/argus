import { describe, expect, it } from '@jest/globals';

import {
  DEFAULT_CONFIG,
  cloneConfig,
  compileExcludeMatcher,
  validateConfig,
  type CodeGuardConfig,
} from '../schema';

describe('validateConfig', () => {
  it('returns the defaults for an absent config', () => {
    const { config, problems } = validateConfig(undefined);
    expect(problems).toEqual([]);
    expect(config.threshold).toEqual({ blockOn: 'Critical', warnOn: 'High' });
    expect(config.excludePaths).toEqual([]);
  });

  it('accepts a complete valid config', () => {
    const { config, problems } = validateConfig({
      threshold: { blockOn: 'High', warnOn: 'Medium' },
      excludePaths: ['dist/**'],
      model: 'deepseek-v4.1-flash',
    });
    expect(problems).toEqual([]);
    expect(config).toEqual({
      threshold: { blockOn: 'High', warnOn: 'Medium' },
      excludePaths: ['dist/**'],
      // Absent from the file, so filled from the defaults — a config written
      // before `remote` existed still has to produce the full shape.
      remote: { maxDeepAnalysisHunks: 5, timeoutMs: 60_000 },
      model: 'deepseek-v4.1-flash',
    });
  });

  it('fills in each threshold independently, so a partial object still works', () => {
    const { config, problems } = validateConfig({ threshold: { blockOn: 'Medium' } });
    expect(problems).toEqual([]);
    expect(config.threshold).toEqual({ blockOn: 'Medium', warnOn: 'High' });
  });

  it('reports an unknown top-level key instead of ignoring it', () => {
    // "excludePath" is a plausible typo for "excludePaths". Ignoring it quietly
    // would leave the developer believing a path was excluded when it was not.
    const { problems } = validateConfig({ excludePath: ['dist/**'] });
    expect(problems).toHaveLength(1);
    expect(problems[0]?.where).toBe('excludePath');
    expect(problems[0]?.message).toContain('unknown setting');
  });

  it('rejects a misspelled severity and says what it fell back to', () => {
    const { config, problems } = validateConfig({ threshold: { blockOn: 'Critcal' } });
    expect(problems).toHaveLength(1);
    expect(problems[0]?.where).toBe('threshold.blockOn');
    expect(problems[0]?.message).toContain('Using "Critical"');
    expect(config.threshold.blockOn).toBe('Critical');
  });

  it('rejects a threshold that is not an object', () => {
    const { problems } = validateConfig({ threshold: 'Critical' });
    expect(problems).toHaveLength(1);
    expect(problems[0]?.where).toBe('threshold');
  });

  it('rejects excludePaths that is not an array', () => {
    const { config, problems } = validateConfig({ excludePaths: 'dist/**' });
    expect(problems[0]?.where).toBe('excludePaths');
    expect(config.excludePaths).toEqual([]);
  });

  it('reports each bad excludePaths entry by index and keeps the good ones', () => {
    const { config, problems } = validateConfig({ excludePaths: ['dist/**', 42, '', 'vendor/'] });
    expect(problems.map((problem) => problem.where)).toEqual(['excludePaths[1]', 'excludePaths[2]']);
    expect(config.excludePaths).toEqual(['dist/**', 'vendor/']);
  });

  it('rejects a non-string model', () => {
    const { config, problems } = validateConfig({ model: 7 });
    expect(problems[0]?.where).toBe('model');
    expect(config.model).toBeUndefined();
  });

  it('rejects a whole config that is not an object', () => {
    const { problems } = validateConfig([1, 2, 3]);
    expect(problems[0]?.message).toContain('must be a JSON object');
  });

  it('does NOT report warnOn above blockOn, which is redundant rather than wrong', () => {
    const { config, problems } = validateConfig({ threshold: { blockOn: 'High', warnOn: 'Critical' } });
    expect(problems).toEqual([]);
    expect(config.threshold).toEqual({ blockOn: 'High', warnOn: 'Critical' });
  });
});

describe('cloneConfig', () => {
  it('produces an equal but independent copy', () => {
    const source: CodeGuardConfig = {
      threshold: { blockOn: 'High', warnOn: 'Medium' },
      excludePaths: ['dist/**'],
      remote: { maxDeepAnalysisHunks: 3, timeoutMs: 1_000 },
      model: 'm',
    };
    const copy = cloneConfig(source);
    expect(copy).toEqual(source);
    expect(copy).not.toBe(source);
    expect(copy.threshold).not.toBe(source.threshold);
    expect(copy.excludePaths).not.toBe(source.excludePaths);
    expect(copy.remote).not.toBe(source.remote);
  });

  it('omits model entirely when the source has none', () => {
    const copy = cloneConfig({
      threshold: { blockOn: 'Critical', warnOn: 'High' },
      excludePaths: [],
      remote: { maxDeepAnalysisHunks: 5, timeoutMs: 60_000 },
    });

    expect('model' in copy).toBe(false);
  });

  it('does not let a caller mutate the shared defaults', () => {
    // The defaults hold the block threshold. If loadConfig handed DEFAULT_CONFIG
    // out directly, one caller's edit would weaken the gate for every later
    // call in the same process.
    const clone = cloneConfig(DEFAULT_CONFIG);
    clone.threshold.blockOn = 'Low';
    clone.excludePaths.push('everything/**');

    expect(DEFAULT_CONFIG.threshold.blockOn).toBe('Critical');
    expect(DEFAULT_CONFIG.excludePaths).toEqual([]);
  });
});

describe('compileExcludeMatcher', () => {
  const matches = (patterns: string[], filePath: string): boolean =>
    compileExcludeMatcher(patterns)(filePath);

  it('never matches when no patterns are configured', () => {
    expect(matches([], 'src/anything.js')).toBe(false);
  });

  it('matches a directory prefix written with a trailing slash', () => {
    expect(matches(['vendor/'], 'vendor/lib.js')).toBe(true);
    expect(matches(['vendor/'], 'vendor/nested/deep.js')).toBe(true);
    expect(matches(['vendor/'], 'src/vendor.js')).toBe(false);
  });

  it('treats ** as spanning directories', () => {
    expect(matches(['dist/**'], 'dist/a.js')).toBe(true);
    expect(matches(['dist/**'], 'dist/nested/b.js')).toBe(true);
  });

  it('anchors a pattern containing a slash to the repository root', () => {
    // "dist/**" must not also exclude a directory called dist somewhere else in
    // the tree, or the config would be doing more than it says.
    expect(matches(['dist/**'], 'src/dist/a.js')).toBe(false);
  });

  it('treats * as staying within one segment', () => {
    expect(matches(['src/*.js'], 'src/a.js')).toBe(true);
    expect(matches(['src/*.js'], 'src/nested/a.js')).toBe(false);
  });

  it('matches a bare name at any depth, so node_modules needs no glob', () => {
    expect(matches(['node_modules'], 'node_modules/a.js')).toBe(true);
    expect(matches(['node_modules'], 'packages/app/node_modules/b.js')).toBe(true);
    expect(matches(['node_modules'], 'mynode_modules/a.js')).toBe(false);
  });

  it('matches a bare glob at any depth', () => {
    expect(matches(['*.min.js'], 'a.min.js')).toBe(true);
    expect(matches(['*.min.js'], 'static/js/a.min.js')).toBe(true);
    expect(matches(['*.min.js'], 'a.js')).toBe(false);
  });

  it('handles **/ for a leading directory wildcard', () => {
    expect(matches(['**/*.spec.ts'], 'a.spec.ts')).toBe(true);
    expect(matches(['**/*.spec.ts'], 'src/deep/a.spec.ts')).toBe(true);
  });

  it('treats ? as exactly one character', () => {
    expect(matches(['src/?.js'], 'src/a.js')).toBe(true);
    expect(matches(['src/?.js'], 'src/ab.js')).toBe(false);
  });

  it('escapes regex metacharacters so they match literally', () => {
    expect(matches(['a+b.js'], 'a+b.js')).toBe(true);
    expect(matches(['a+b.js'], 'aab.js')).toBe(false);
    expect(matches(['a.b.js'], 'axb.js')).toBe(false);
    expect(matches(['(x)/y.js'], '(x)/y.js')).toBe(true);
  });

  it('normalises Windows-style separators in a pattern', () => {
    expect(matches(['dist\\**'], 'dist/a.js')).toBe(true);
  });

  it('ignores a leading ./ that people write out of habit', () => {
    expect(matches(['./dist/**'], 'dist/a.js')).toBe(true);
  });

  it('ORs multiple patterns', () => {
    expect(matches(['dist/**', 'vendor/'], 'vendor/a.js')).toBe(true);
    expect(matches(['dist/**', 'vendor/'], 'src/a.js')).toBe(false);
  });
});
