/**
 * Local Static Engine — regex/pattern detection over diff hunks (FR-8).
 *
 * Detection only. There is deliberately no patch generation here: PRD §5.2 puts
 * auto-patching out of scope for Local Mode, which is why `LocalFinding` has no
 * `suggested_patch` field to fill in.
 *
 * Scope of analysis is ADDED lines only. A vulnerability that this commit
 * deletes is not this commit's problem, and flagging unchanged context would
 * report issues the developer never introduced — which is precisely the noise
 * that gets a pre-commit gate switched off.
 *
 * Whole-line comments are skipped as well, for the same anti-noise reason: a
 * comment mentioning a dangerous call is documentation, not a vulnerability.
 * See source-file.ts for exactly which lines qualify and why that skip is safe.
 */

import { parseDiff } from '../diff';
import { DEFAULT_RULES, rulesForFile, type Rule } from './rules';
import { isWholeLineComment } from './source-file';
import type { LocalFinding } from './types';

export { commentPrefixesFor, fileExtension, isWholeLineComment } from './source-file';

export type { LocalFinding } from './types';
export type { Rule } from './rules';
export { DEFAULT_RULES, rulesForFile } from './rules';

export interface LocalScanOptions {
  /**
   * Rule set to run. Defaults to the built-in set. Exists so FR-13
   * (user-defined rules) or a config-driven subset can be injected later
   * without touching the scanner.
   */
  rules?: readonly Rule[];
  /**
   * Predicate over repo-relative paths; return true to skip a file entirely.
   *
   * A predicate rather than a list of globs on purpose: glob syntax is a
   * configuration concern, and taking a plain function keeps the engine free of
   * it (and trivially testable). `compileExcludeMatcher` in config/schema.ts
   * adapts the configured `excludePaths` into one of these.
   *
   * Applied before rule selection, so an excluded file costs nothing at all.
   */
  exclude?: (filePath: string) => boolean;
}

/**
 * Runs the rule set over a unified diff.
 *
 * @param diff Raw output of `git diff --cached` (unified diff format).
 * @returns One finding per matched rule per line, in diff order (file, then
 *          line, then rule). Never throws on malformed input — an unparseable
 *          diff yields no findings rather than crashing a pre-commit hook.
 */
export async function runLocalScan(
  diff: string,
  options: LocalScanOptions = {},
): Promise<LocalFinding[]> {
  const rules = options.rules ?? DEFAULT_RULES;
  const findings: LocalFinding[] = [];

  for (const file of parseDiff(diff)) {
    // Binary content cannot be matched line-wise, and git gives us no hunks for it.
    if (file.isBinary) continue;

    // Config-driven path exclusion (PRD §5.1). Skipped before rule selection so
    // an excluded file does no work at all.
    if (options.exclude?.(file.path) === true) continue;

    const applicable = rulesForFile(rules, file.path);
    if (applicable.length === 0) continue;

    for (const hunk of file.hunks) {
      for (const line of hunk.lines) {
        if (line.kind !== 'add' || line.newLine === null) continue;

        // A whole-line comment cannot contain code, so scanning it can only
        // produce false positives (e.g. a comment explaining a call that was
        // removed). This is safe precisely because the skip is limited to lines
        // that are *entirely* comments — see source-file.ts.
        if (isWholeLineComment(file.path, line.content)) continue;

        for (const rule of applicable) {
          // Patterns are non-global by contract (see the Rule interface), so
          // exec() carries no lastIndex state between iterations.
          const match = rule.pattern.exec(line.content);
          if (match === null) continue;
          if (rule.refine !== undefined && !rule.refine(line.content, match)) continue;

          findings.push({
            file: file.path,
            line: line.newLine,
            ruleId: rule.id,
            severity: rule.severity,
            message: rule.message,
          });
        }
      }
    }
  }

  return findings;
}
