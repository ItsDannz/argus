/**
 * Unified-diff parser (FR-1).
 *
 * CodeGuard never scans whole files — it scans the staged diff. That makes this
 * module the foundation the rest of the tool stands on: the Local Engine walks
 * its output line by line, and Remote Mode (Phase 4) slices the same structures
 * into hunks to send to the API.
 *
 * The one thing this parser must get exactly right is LINE NUMBERS. Every
 * finding CodeGuard reports is anchored to a line in the *new* version of the
 * file, and getting that off by one — or counting a deleted line as if it were
 * added — would point developers at the wrong code. So the number tracking is
 * explicit rather than inferred: each hunk resets its own counters, and each
 * line type advances only the counters it actually affects.
 *
 * Deliberately NOT supported: `diff --git` line parsing for path names (only
 * used as a fallback for binary files), non-UTF8 path escaping, and combined
 * merge diffs (`diff --cc`). None of these occur for `git diff --cached`.
 */

export type DiffLineKind = 'add' | 'del' | 'context';

export interface DiffLine {
  kind: DiffLineKind;
  /** Line text with the leading "+", "-", or " " marker removed. */
  content: string;
  /** 1-based line number in the OLD file, or null for added lines. */
  oldLine: number | null;
  /** 1-based line number in the NEW file, or null for deleted lines. */
  newLine: number | null;
}

export interface DiffHunk {
  /** The raw `@@ -1,5 +1,7 @@` header, preserved for round-tripping. */
  header: string;
  oldStart: number;
  oldCount: number;
  newStart: number;
  newCount: number;
  lines: DiffLine[];
}

export type DiffFileStatus = 'added' | 'modified' | 'deleted' | 'renamed';

export interface DiffFile {
  /** Path in the new tree, without the "b/" prefix. For deletions, the old path. */
  path: string;
  /** Previous path, when the file was renamed. Otherwise null. */
  previousPath: string | null;
  status: DiffFileStatus;
  isBinary: boolean;
  hunks: DiffHunk[];
}

/** Matches `@@ -oldStart,oldCount +newStart,newCount @@` (counts optional). */
const HUNK_HEADER = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

/**
 * Matches the `diff --git "a/x" "b/y"` line, tolerating git's quoted form for
 * paths containing spaces or special characters.
 */
const DIFF_GIT_HEADER =
  /^diff --git (?:"((?:[^"\\]|\\.)*)"|(\S+)) (?:"((?:[^"\\]|\\.)*)"|(\S+))$/;

/**
 * Reverses git's quoting of a path. Git wraps paths in double quotes and
 * backslash-escapes when they contain spaces or control characters.
 *
 * Limitation: octal escapes (`\303\251` for non-ASCII bytes) are left as-is
 * rather than decoded — `git diff --cached` only quotes for special characters,
 * and undecoding them would require byte-level handling for no practical gain.
 */
function unquotePath(raw: string): string {
  const trimmed = raw.trim();
  if (!(trimmed.startsWith('"') && trimmed.endsWith('"')) || trimmed.length < 2) {
    return trimmed;
  }
  const inner = trimmed.slice(1, -1);
  return inner.replace(/\\(.)/g, (_full, char: string) => {
    switch (char) {
      case 'n':
        return '\n';
      case 't':
        return '\t';
      case 'r':
        return '\r';
      case '"':
        return '"';
      case '\\':
        return '\\';
      default:
        return char;
    }
  });
}

/**
 * Strips the `a/` or `b/` prefix git adds, and turns the `/dev/null` sentinel
 * into null (which is how git signals "this side does not exist" for added and
 * deleted files).
 */
function normalizePath(raw: string): string | null {
  const unquoted = unquotePath(raw);
  if (unquoted === '/dev/null') return null;
  if (unquoted.startsWith('a/') || unquoted.startsWith('b/')) {
    return unquoted.slice(2);
  }
  return unquoted;
}

/**
 * Parses one path token from a `diff --git` line, preferring the quoted capture
 * group when present.
 */
function parseDiffGitToken(quoted: string | undefined, bare: string | undefined): string | null {
  if (quoted !== undefined) return normalizePath(`"${quoted}"`);
  if (bare !== undefined) return normalizePath(bare);
  return null;
}

/**
 * Extracts the path git reports for a binary file, from either the
 * `diff --git` line or the `Binary files a/x and b/y differ` line.
 *
 * Needed because binary diffs carry no `---`/`+++` lines, so the usual path
 * source is absent. Binary files are never scanned — this exists so the CLI can
 * still name them accurately instead of reporting an empty path.
 */
function parseBinaryPath(line: string): string | null {
  const match = /^Binary files (.*) and (.*) differ$/.exec(line);
  if (match) {
    // Paths may themselves contain " and ", so the greedy first group is the
    // safer guess for the old side and the remainder is the new side.
    return normalizePath(match[2] ?? '');
  }
  return null;
}

/**
 * Parses a unified diff into per-file, per-hunk, per-line structures.
 *
 * @param raw Raw output of `git diff --cached`.
 * @returns One entry per changed file, in diff order. Never throws on
 *          malformed input — unrecognised lines are skipped so that a diff the
 *          parser does not fully understand can never crash a pre-commit hook.
 */
export function parseDiff(raw: string): DiffFile[] {
  const files: DiffFile[] = [];

  let current: DiffFile | null = null;
  let hunk: DiffHunk | null = null;

  // Running line counters, valid only while inside a hunk.
  let oldLine = 0;
  let newLine = 0;

  // Section state, resolved into `current` once the +++ line arrives.
  let oldPath: string | null = null;
  let declaredNew = false;
  let declaredDeleted = false;
  let declaredRenamed = false;

  /**
   * Resolves the final status and path for the file just finished.
   *
   * Status is decided HERE rather than in the `+++` branch because a pure rename
   * carries no `---`/`+++` lines at all — git emits only `rename from`/`rename
   * to`. Deciding at the end means a rename is still classified correctly, and
   * the flags are all known by this point regardless of which lines appeared.
   */
  const finishFile = (): void => {
    if (current !== null) {
      if (declaredDeleted) {
        current.status = 'deleted';
      } else if (declaredNew || current.previousPath === null) {
        current.status = 'added';
      } else if (declaredRenamed) {
        current.status = 'renamed';
      } else {
        current.status = 'modified';
      }

      // A deleted file has no new-side path, so report the path it used to have.
      if (current.path === '' && current.previousPath !== null) {
        current.path = current.previousPath;
      }
      files.push(current);
    }
    current = null;
    hunk = null;
    oldPath = null;
    declaredNew = false;
    declaredDeleted = false;
    declaredRenamed = false;
  };

  for (const line of raw.split(/\r?\n/)) {
    if (line.startsWith('diff --git ')) {
      finishFile();
      const match = DIFF_GIT_HEADER.exec(line);
      const headerOld = match ? parseDiffGitToken(match[1], match[2]) : null;
      const headerNew = match ? parseDiffGitToken(match[3], match[4]) : null;
      current = {
        path: headerNew ?? headerOld ?? '',
        previousPath: null,
        status: 'modified',
        isBinary: false,
        hunks: [],
      };
      continue;
    }

    if (current === null) continue;

    // --- File-level metadata (appears before the first hunk) ---
    if (line.startsWith('new file mode')) {
      declaredNew = true;
      continue;
    }
    if (line.startsWith('deleted file mode')) {
      declaredDeleted = true;
      continue;
    }
    if (line.startsWith('rename from ')) {
      declaredRenamed = true;
      current.previousPath = normalizePath(line.slice('rename from '.length));
      continue;
    }
    if (line.startsWith('--- ')) {
      oldPath = normalizePath(line.slice(4));
      continue;
    }
    if (line.startsWith('+++ ')) {
      const newPath = normalizePath(line.slice(4));
      current.previousPath = oldPath;

      // For a deletion the new side is /dev/null, so keep the old path.
      current.path = newPath ?? oldPath ?? current.path;
      continue;
    }

    if (line.startsWith('Binary files ') || line.startsWith('GIT binary patch')) {
      current.isBinary = true;
      const binaryPath = parseBinaryPath(line);
      // Only adopt this path if the +++ line never gave us one, so a real path
      // is never overwritten by the looser binary-line heuristic.
      if (binaryPath !== null && current.path === '') current.path = binaryPath;
      continue;
    }

    // --- Hunk header ---
    const hunkHeader = HUNK_HEADER.exec(line);
    if (hunkHeader) {
      const oldStart = Number(hunkHeader[1]);
      const newStart = Number(hunkHeader[3]);
      // A missing count means "1 line", per the unified diff format.
      const oldCount = hunkHeader[2] === undefined ? 1 : Number(hunkHeader[2]);
      const newCount = hunkHeader[4] === undefined ? 1 : Number(hunkHeader[4]);

      hunk = { header: line, oldStart, oldCount, newStart, newCount, lines: [] };
      current.hunks.push(hunk);
      oldLine = oldStart;
      newLine = newStart;
      continue;
    }

    // --- Hunk body ---
    if (hunk === null) continue;

    const marker = line.charAt(0);
    if (marker === '\\') {
      // "\ No newline at end of file" — metadata about the previous line, and
      // crucially NOT a line of its own, so no counter may advance here.
      continue;
    }
    if (!isHunkBodyMarker(marker)) {
      // Any line that is not add/del/context means the hunk has ended. This is
      // also how the trailing "" from split() on a final newline is ignored.
      hunk = null;
      continue;
    }

    if (marker === '+') {
      hunk.lines.push({ kind: 'add', content: line.slice(1), oldLine: null, newLine });
      newLine += 1;
    } else if (marker === '-') {
      hunk.lines.push({ kind: 'del', content: line.slice(1), oldLine, newLine: null });
      oldLine += 1;
    } else {
      // ' ' — unchanged context: present in BOTH versions, so both advance.
      hunk.lines.push({ kind: 'context', content: line.slice(1), oldLine, newLine });
      oldLine += 1;
      newLine += 1;
    }
  }

  finishFile();
  return files;
}

/**
 * Returns true when `marker` is a valid hunk-body line prefix.
 *
 * A line that fails this check marks the end of the current hunk — which is
 * also how the trailing "" produced by split() on a final newline gets ignored.
 */
function isHunkBodyMarker(marker: string): boolean {
  return marker === '+' || marker === '-' || marker === ' ';
}

/**
 * Convenience accessor: every added line across a file's hunks, in order.
 *
 * Added lines are the only ones CodeGuard analyses — a vulnerability that a
 * commit *removes* is not that commit's problem, and flagging unchanged context
 * would report issues the developer did not introduce.
 */
export function addedLines(file: DiffFile): DiffLine[] {
  const result: DiffLine[] = [];
  for (const hunk of file.hunks) {
    for (const line of hunk.lines) {
      if (line.kind === 'add') result.push(line);
    }
  }
  return result;
}
