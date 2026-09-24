/**
 * `.codeguardrc.json` schema, defaults, and validation (PRD §5.1, §9.1).
 *
 * Validation returns problems rather than throwing. The caller decides what a
 * malformed config means — the CLI prints them and carries on with defaults,
 * which is deliberate and explained where the decision is made (see
 * load.ts and hooks/pre-commit.ts).
 *
 * The defaults are chosen to be the least surprising state for a developer who
 * has never created this file: block only on Critical, warn on High (the
 * threshold agreed for this project), and exclude nothing, so the tool never
 * silently ignores a path the developer did not ask it to ignore.
 */

import type { Severity } from '../prompts/security-agent-prompts';
import { isSeverity } from '../severity';

export const CONFIG_FILENAME = '.codeguardrc.json';

export interface ThresholdConfig {
  /** Findings at or above this severity block the commit. */
  blockOn: Severity;
  /** Findings at or above this severity (but below `blockOn`) are reported but allowed. */
  warnOn: Severity;
}

export interface CodeGuardConfig {
  threshold: ThresholdConfig;
  excludePaths: string[];
  /** Model id for Remote Mode. Consumed in Phase 4; validated here so the schema is stable. */
  model?: string;
}

/** A deeply-readonly view, for values that must never be mutated in place. */
export interface ReadonlyCodeGuardConfig {
  readonly threshold: Readonly<ThresholdConfig>;
  readonly excludePaths: readonly string[];
  readonly model?: string;
}

/**
 * The defaults, chosen to be the least surprising state for a developer who has
 * never created this file: block only on Critical, warn on High (the threshold
 * agreed for this project), and exclude nothing — so the tool never silently
 * ignores a path nobody asked it to ignore.
 */
export const DEFAULT_CONFIG: ReadonlyCodeGuardConfig = {
  threshold: { blockOn: 'Critical', warnOn: 'High' },
  excludePaths: [],
};

/** A single thing wrong with a config file, addressed by dotted path. */
export interface ConfigProblem {
  /** Dotted path to the offending value, e.g. "threshold.blockOn". */
  where: string;
  message: string;
}

/**
 * Deep-copies a config so callers can never mutate {@link DEFAULT_CONFIG}.
 *
 * Without this, `loadConfig()` returning DEFAULT_CONFIG directly would let one
 * caller's edit leak into every later call in the same process — and since that
 * object holds the block threshold, the leak would be a silently weakened
 * security gate.
 */
export function cloneConfig(config: ReadonlyCodeGuardConfig): CodeGuardConfig {
  return {
    threshold: { blockOn: config.threshold.blockOn, warnOn: config.threshold.warnOn },
    excludePaths: [...config.excludePaths],
    ...(config.model === undefined ? {} : { model: config.model }),
  };
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const KNOWN_KEYS = new Set(['threshold', 'excludePaths', 'model']);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function validateThreshold(raw: unknown, problems: ConfigProblem[]): ThresholdConfig {
  const threshold: ThresholdConfig = { ...DEFAULT_CONFIG.threshold };
  if (raw === undefined) return threshold;

  if (!isPlainObject(raw)) {
    problems.push({ where: 'threshold', message: 'must be an object, e.g. { "blockOn": "Critical" }.' });
    return threshold;
  }

  for (const key of ['blockOn', 'warnOn'] as const) {
    const value = raw[key];
    if (value === undefined) continue;
    if (!isSeverity(value)) {
      problems.push({
        where: `threshold.${key}`,
        message: `must be one of Critical, High, Medium, Low — got ${JSON.stringify(value)}. Using "${threshold[key]}".`,
      });
      continue;
    }
    threshold[key] = value;
  }

  return threshold;
}

function validateExcludePaths(raw: unknown, problems: ConfigProblem[]): string[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) {
    problems.push({
      where: 'excludePaths',
      message: 'must be an array of strings, e.g. ["dist/**", "vendor/"]. Ignoring it.',
    });
    return [];
  }

  const paths: string[] = [];
  raw.forEach((entry, index) => {
    if (typeof entry !== 'string' || entry.trim() === '') {
      problems.push({
        where: `excludePaths[${index}]`,
        message: `must be a non-empty string — got ${JSON.stringify(entry)}. Skipping it.`,
      });
      return;
    }
    paths.push(entry);
  });
  return paths;
}

/**
 * Validates an already-parsed config value.
 *
 * Unknown top-level keys are reported as problems rather than ignored. That is
 * on purpose: `"excludePath"` (singular) is a plausible typo for
 * `"excludePaths"`, and silently ignoring it would leave a developer believing
 * they had excluded a path when they had not.
 *
 * A `warnOn` above `blockOn` is NOT reported. It is redundant rather than
 * wrong — everything at `warnOn` also blocks, so no warning is ever printed and
 * the stricter threshold wins. Rejecting it would be pedantry.
 */
export function validateConfig(raw: unknown): { config: CodeGuardConfig; problems: ConfigProblem[] } {
  const problems: ConfigProblem[] = [];

  if (raw === undefined || raw === null) {
    return { config: cloneConfig(DEFAULT_CONFIG), problems };
  }

  if (!isPlainObject(raw)) {
    problems.push({ where: '', message: 'config must be a JSON object. Using defaults.' });
    return { config: cloneConfig(DEFAULT_CONFIG), problems };
  }

  for (const key of Object.keys(raw)) {
    if (!KNOWN_KEYS.has(key)) {
      problems.push({
        where: key,
        message: `unknown setting — ignoring it. Known settings: ${[...KNOWN_KEYS].join(', ')}.`,
      });
    }
  }

  const threshold = validateThreshold(raw['threshold'], problems);
  const excludePaths = validateExcludePaths(raw['excludePaths'], problems);

  let model: string | undefined;
  if (raw['model'] !== undefined) {
    if (typeof raw['model'] === 'string' && raw['model'].trim() !== '') {
      model = raw['model'];
    } else {
      problems.push({
        where: 'model',
        message: `must be a non-empty string — got ${JSON.stringify(raw['model'])}. Ignoring it.`,
      });
    }
  }

  return { config: { threshold, excludePaths, ...(model === undefined ? {} : { model }) }, problems };
}

// ---------------------------------------------------------------------------
// Path exclusion
// ---------------------------------------------------------------------------

/** Regex metacharacters that must be escaped when compiling a glob. */
const GLOB_METACHARACTER = /[\\^$.|+()[\]{}]/;

/**
 * Compiles one glob into a regex over repo-relative POSIX paths.
 *
 * Supported, and deliberately no more:
 *   `*`   — any run of characters within ONE path segment
 *   `**`  — any run of characters across segments
 *   `?`   — exactly one character within a segment
 *
 * This is not a full .gitignore implementation. Negation (`!pattern`) and
 * character classes (`[abc]`) are not supported, and are not needed for the
 * job §5.1 gives excludePaths. Hand-rolling this rather than pulling in a glob
 * package keeps the dependency list at what PRD §9.1 names.
 *
 * A pattern containing no `/` matches at any depth, so `node_modules` excludes
 * the directory and everything under it. A pattern containing a `/` is anchored
 * to the repo root, so `dist/**` excludes only the top-level `dist`.
 */
function globToRegExp(pattern: string): RegExp {
  // Backslashes are normalised to '/' so a config written on Windows works on
  // macOS and Linux (and in reverse).
  let source = pattern.trim().replace(/\\/g, '/');
  if (source.startsWith('./')) source = source.slice(2);
  if (source.startsWith('/')) source = source.slice(1);
  // A trailing slash names a directory: the intent is everything inside it.
  if (source.endsWith('/')) source += '**';

  let body = '';
  for (let i = 0; i < source.length; i++) {
    const char = source[i]!;
    if (char === '*') {
      if (source[i + 1] === '*') {
        i++;
        if (source[i + 1] === '/') {
          i++;
          body += '(?:[^/]+/)*'; // "**/" — zero or more directory segments
        } else {
          body += '.*'; // trailing "**" — swallow everything that follows
        }
      } else {
        body += '[^/]*';
      }
    } else if (char === '?') {
      body += '[^/]';
    } else if (GLOB_METACHARACTER.test(char)) {
      body += `\\${char}`;
    } else {
      body += char;
    }
  }

  const anchored = source.includes('/');
  return new RegExp(anchored ? `^${body}$` : `^(?:.*/)?${body}(?:/.*)?$`);
}

/**
 * Builds the predicate handed to the scan engine as `exclude`.
 *
 * The engine takes a predicate rather than the glob list on purpose: knowing
 * about glob syntax is a config concern, and keeping it out of the engine means
 * the engine stays testable with a plain function.
 */
export function compileExcludeMatcher(patterns: readonly string[]): (filePath: string) => boolean {
  if (patterns.length === 0) return () => false;
  const matchers = patterns.map(globToRegExp);
  return (filePath: string) => matchers.some((matcher) => matcher.test(filePath));
}
