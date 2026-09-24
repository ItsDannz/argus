/**
 * Reads `.codeguardrc.json` from a repository root (PRD §9.1).
 *
 * Scope: the repository root only. A config in a parent directory or in a
 * subdirectory is not consulted. Monorepo support (walking up, or per-package
 * configs) is not in the PRD and is deliberately not guessed at here.
 *
 * This function never throws. A missing file is the normal case; a broken file
 * yields defaults plus a list of problems for the caller to surface. Whether
 * that should stop a commit is a policy decision, and it is made in
 * hooks/pre-commit.ts, not here.
 */

import { readFile } from 'node:fs/promises';
import path from 'node:path';

import {
  CONFIG_FILENAME,
  cloneConfig,
  compileExcludeMatcher,
  DEFAULT_CONFIG,
  validateConfig,
  type CodeGuardConfig,
  type ConfigProblem,
} from './schema';

export interface LoadedConfig {
  config: CodeGuardConfig;
  /** Absolute path of the file that was read, or null when defaults were used. */
  path: string | null;
  /** Everything wrong with the file, in the order found. Empty when it was clean. */
  problems: ConfigProblem[];
  /** Predicate over repo-relative paths, built from `excludePaths`. */
  isExcluded: (filePath: string) => boolean;
}

function defaults(path_: string | null, problems: ConfigProblem[]): LoadedConfig {
  const config = cloneConfig(DEFAULT_CONFIG);
  return {
    config,
    path: path_,
    problems,
    isExcluded: compileExcludeMatcher(config.excludePaths),
  };
}

/** One-line rendering of a problem, for the "your config is broken" warning. */
export function formatProblem(problem: ConfigProblem): string {
  return problem.where === ''
    ? problem.message
    : `${problem.where}: ${problem.message}`;
}

/**
 * Loads and validates the config for a repository.
 *
 * @param repoRoot Repository root. The config is read from exactly here.
 */
export async function loadConfig(repoRoot: string): Promise<LoadedConfig> {
  const configPath = path.join(repoRoot, CONFIG_FILENAME);

  let text: string;
  try {
    text = await readFile(configPath, 'utf8');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    // Absent config is the expected state for a project that has not opted in.
    // Any other read failure is worth telling the user about — a config that
    // exists but cannot be read must not look like "no config".
    if (code === 'ENOENT') return defaults(null, []);
    return defaults(configPath, [
      { where: '', message: `could not be read (${code ?? 'unknown error'}). Using defaults.` },
    ]);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return defaults(configPath, [{ where: '', message: `is not valid JSON — ${message}. Using defaults.` }]);
  }

  const { config, problems } = validateConfig(parsed);
  return {
    config,
    path: configPath,
    problems,
    isExcluded: compileExcludeMatcher(config.excludePaths),
  };
}

export { CONFIG_FILENAME };
export type { CodeGuardConfig, ConfigProblem };
