import { mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it } from '@jest/globals';

import { CONFIG_FILENAME } from '../schema';
import { formatProblem, loadConfig } from '../load';

async function tempRoot(): Promise<string> {
  return mkdtemp(path.join(tmpdir(), 'codeguard-config-'));
}

async function writeConfig(root: string, contents: string): Promise<string> {
  const target = path.join(root, CONFIG_FILENAME);
  await writeFile(target, contents, 'utf8');
  return target;
}

describe('loadConfig', () => {
  it('falls back to defaults with no problems when the file is absent', async () => {
    const root = await tempRoot();
    const loaded = await loadConfig(root);

    expect(loaded.path).toBeNull();
    expect(loaded.problems).toEqual([]);
    expect(loaded.config.threshold).toEqual({ blockOn: 'Critical', warnOn: 'High' });
    expect(loaded.config.excludePaths).toEqual([]);
  });

  it('loads a valid file and records where it came from', async () => {
    const root = await tempRoot();
    const target = await writeConfig(
      root,
      JSON.stringify({ threshold: { blockOn: 'Medium' }, excludePaths: ['dist/**'] }),
    );

    const loaded = await loadConfig(root);
    expect(loaded.path).toBe(target);
    expect(loaded.problems).toEqual([]);
    expect(loaded.config.threshold).toEqual({ blockOn: 'Medium', warnOn: 'High' });
    // The matcher must be built from the file's contents, not the defaults.
    expect(loaded.isExcluded('dist/a.js')).toBe(true);
    expect(loaded.isExcluded('src/a.js')).toBe(false);
  });

  it('does not exclude anything when the file configures nothing', async () => {
    const root = await tempRoot();
    await writeConfig(root, '{}');

    const loaded = await loadConfig(root);
    expect(loaded.isExcluded('dist/a.js')).toBe(false);
  });

  it('reports invalid JSON, keeps the path, and uses defaults', async () => {
    const root = await tempRoot();
    const target = await writeConfig(root, '{ "threshold": ');

    const loaded = await loadConfig(root);
    expect(loaded.path).toBe(target);
    expect(loaded.problems).toHaveLength(1);
    expect(loaded.problems[0]?.message).toContain('not valid JSON');
    expect(loaded.config.threshold.blockOn).toBe('Critical');
  });

  it('reports schema problems from a syntactically valid file', async () => {
    const root = await tempRoot();
    await writeConfig(root, JSON.stringify({ threshold: { blockOn: 'Nope' } }));

    const loaded = await loadConfig(root);
    expect(loaded.problems).toHaveLength(1);
    expect(loaded.problems[0]?.where).toBe('threshold.blockOn');
  });

  it('reports a config path that exists but cannot be read as a file', async () => {
    // A directory named like the config must not be mistaken for "no config":
    // that would silently discard a configuration the developer believes is
    // active.
    const root = await tempRoot();
    await mkdir(path.join(root, CONFIG_FILENAME));

    const loaded = await loadConfig(root);
    expect(loaded.path).toBe(path.join(root, CONFIG_FILENAME));
    expect(loaded.problems).toHaveLength(1);
    expect(loaded.problems[0]?.message).toContain('could not be read');
  });
});

describe('formatProblem', () => {
  it('prefixes the setting name when there is one', () => {
    expect(formatProblem({ where: 'threshold.blockOn', message: 'bad' })).toBe('threshold.blockOn: bad');
  });

  it('omits the prefix for file-level problems', () => {
    expect(formatProblem({ where: '', message: 'bad' })).toBe('bad');
  });
});
