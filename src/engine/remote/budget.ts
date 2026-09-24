/**
 * Preparing a diff for transmission.
 *
 * Both functions here operate on raw diff text and are remote-mode only: Local
 * Mode applies `excludePaths` per file as it walks (see engine/local/index.ts),
 * because it never has to hand the diff to anyone else. Remote Mode filters the
 * text instead, which is strictly better for two reasons — an excluded file is
 * never transmitted at all, and tokens are not spent on code whose findings
 * would be discarded on the way back.
 *
 * Every function here drops WHOLE file sections, never partial ones. A diff with
 * a hunk header promising more lines than follow is structurally broken, and the
 * model's line numbers are matched back to hunks — so a mangled diff would not
 * just look wrong, it would silently misplace answers.
 */

/** Matches the `diff --git a/x b/y` line, capturing the raw path tokens. */
const DIFF_GIT_LINE = /^diff --git (?:"((?:[^"\\]|\\.)*)"|(\S+)) (?:"((?:[^"\\]|\\.)*)"|(\S+))$/;

/**
 * A generous ceiling on the triage payload.
 *
 * Roughly 100k tokens of diff. Beyond this the request is likely to be slow or
 * refused, and the cost of a single commit's review stops being proportionate to
 * the commit. It is a ceiling, not a target — an ordinary commit is three orders
 * of magnitude smaller.
 */
export const MAX_TRIAGE_CHARS = 400_000;

export interface DiffSection {
  /** The section's text, starting at its `diff --git` line. */
  text: string;
  /** New-side path, or "" when it could not be determined. */
  path: string;
  /** Whether a `diff --git` line opened this section. */
  isFile: boolean;
}

/**
 * Splits a diff into per-file sections at `diff --git` boundaries.
 *
 * Any preamble before the first `diff --git` is returned as a non-file section,
 * so a caller can reassemble the text exactly. `git diff --cached` does not
 * produce one, but a diff read from a file might.
 */
export function splitSections(diff: string): DiffSection[] {
  const sections: DiffSection[] = [];
  let current: string[] = [];
  let currentIsFile = false;
  let path = '';

  const flush = (): void => {
    if (current.length === 0) return;
    sections.push({ text: current.join('\n'), path, isFile: currentIsFile });
    current = [];
    path = '';
    currentIsFile = false;
  };

  for (const line of diff.split('\n')) {
    if (line.startsWith('diff --git ')) {
      flush();
      currentIsFile = true;
    } else if (currentIsFile && line.startsWith('+++ ')) {
      const named = line.slice(4).trim();
      if (named !== '/dev/null') path = named.replace(/^[ab]\//, '');
    } else if (currentIsFile && path === '' && !line.startsWith('--- ')) {
      // A binary or pure-rename section has no `+++` line, so fall back to the
      // `diff --git` header's second path.
      const match = DIFF_GIT_LINE.exec(current[0] ?? '');
      const fallback = match?.[3] ?? match?.[4];
      if (fallback !== undefined) path = fallback.replace(/^[ab]\//, '').replace(/^"|"$/g, '');
    }
    current.push(line);
  }
  flush();

  return sections;
}

export interface FilterResult {
  diff: string;
  /** Paths removed, in diff order. Reported so an exclusion is never invisible. */
  excluded: string[];
}

/**
 * Removes whole file sections whose path the predicate rejects.
 *
 * @param isExcluded Predicate over repo-relative POSIX paths.
 */
export function filterExcludedFiles(diff: string, isExcluded: (path: string) => boolean): FilterResult {
  const excluded: string[] = [];
  const kept = splitSections(diff).filter((section) => {
    if (!section.isFile || section.path === '') return true;
    if (!isExcluded(section.path)) return true;
    excluded.push(section.path);
    return false;
  });

  return { diff: kept.map((section) => section.text).join('\n'), excluded };
}

export interface TruncateResult {
  diff: string;
  /**
   * Files dropped to fit the budget, in diff order.
   *
   * Returned in full rather than counted, because the caller must say which
   * files went unexamined. A partial scan presented as a whole one is the
   * failure mode this whole module exists to avoid.
   */
  omitted: string[];
  /** True when even the first file did not fit, leaving nothing to send. */
  empty: boolean;
}

/**
 * Drops trailing file sections until the diff fits the budget.
 *
 * Drops from the END rather than the middle: the diff is in the order the
 * developer staged things, and the earliest changes are the ones most likely to
 * be the commit's point. This is a heuristic, which is exactly why the result
 * names every file it dropped instead of quietly getting smaller.
 */
export function truncateToBudget(diff: string, budget = MAX_TRIAGE_CHARS): TruncateResult {
  // The early return still has to answer `empty` honestly. An empty diff — or
  // one whose every file was excluded before it got here — has no file sections,
  // and reporting `empty: false` would send the caller on to make an API call
  // about nothing. That is a wasted request at best, and an invitation for the
  // model to invent findings about an empty prompt at worst.
  if (diff.length <= budget) {
    const isScannable = splitSections(diff).some((section) => section.isFile);
    return { diff: isScannable ? diff : '', omitted: [], empty: !isScannable };
  }

  const sections = splitSections(diff);
  const kept: DiffSection[] = [];
  const omitted: string[] = [];
  let size = 0;

  for (const section of sections) {
    if (kept.length > 0 && size + section.text.length > budget) {
      omitted.push(section.path === '' ? '(unnamed section)' : section.path);
      continue;
    }
    // The first file is always kept even if it alone busts the budget: sending
    // one large file is strictly more useful than sending nothing, and the
    // alternative is reporting a scan that never happened.
    kept.push(section);
    size += section.text.length + 1;
  }

  const fileSections = kept.filter((section) => section.isFile);

  return {
    diff: kept.map((section) => section.text).join('\n'),
    omitted,
    empty: fileSections.length === 0,
  };
}
