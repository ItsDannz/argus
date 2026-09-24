/**
 * Shared test helpers.
 *
 * Not a `.test.ts` file, so Jest will not try to run it as a suite.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Absolute path to the fixture directory.
 *
 * Resolved from `__dirname` (src/engine/local/__tests__) rather than
 * `process.cwd()` so the tests do not break if Jest is invoked from a
 * subdirectory.
 */
export const FIXTURE_ROOT = join(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  'test-fixtures',
  'local-engine',
);

/** Reads a fixture source file from `test-fixtures/local-engine/`. */
export function readFixture(name: string): string {
  return readFileSync(join(FIXTURE_ROOT, name), 'utf8');
}

/** Splits fixture source into lines, dropping the trailing empty element. */
export function fixtureLines(content: string): string[] {
  const lines = content.split(/\r?\n/);
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
  return lines;
}

/**
 * Wraps source code in a synthetic "new file" diff, exactly as
 * `git diff --cached` renders a file that did not exist before.
 *
 * This is how fixtures are fed to the engine: writing fixtures as ordinary
 * readable source files beats hand-maintaining diff strings, and every line
 * being an added line is the strongest case for the scanner to exercise.
 */
export function newFileDiff(path: string, content: string): string {
  const lines = fixtureLines(content);
  return [
    `diff --git a/${path} b/${path}`,
    'new file mode 100644',
    'index 0000000..1111111',
    '--- /dev/null',
    `+++ b/${path}`,
    `@@ -0,0 +1,${lines.length} @@`,
    ...lines.map((line) => `+${line}`),
    '',
  ].join('\n');
}

/** Convenience: wrap fixture source under a plausible repo path. */
export function diffForFixture(fixtureName: string, repoPath: string): string {
  return newFileDiff(repoPath, readFixture(fixtureName));
}
