/**
 * Turning the model's `suggested_patch` into something that can be applied.
 *
 * ─── Why this exists ─────────────────────────────────────────────────────────
 * `suggested_patch` is model output, and it is not a valid patch by
 * construction. Two live samples of the same fixture showed the shape it
 * actually comes back in: hunk headers whose stated line counts disagree with
 * the body underneath them (`@@ -11,2 +11,2 @@` over two `-` lines and one `+`
 * line), and no `--- a/…` / `+++ b/…` file header at all.
 *
 * The count defect is fatal. `parsePatch` rejects the whole patch — "Removed
 * line count did not match for hunk at line 3" — so the applier never gets to
 * try, and the developer sees a finding they cannot fix with one keystroke. The
 * missing header is not fatal: `parsePatch` and `applyPatch` both accept a
 * hunk-only patch, verified directly against diff@9 rather than assumed. It is
 * added here anyway, because a patch that leaves this module should be a
 * complete file diff that also works with `git apply` if it is copied out.
 *
 * ─── What is repaired, and what is refused ───────────────────────────────────
 * Repaired, because the correct value is derivable from the body and nothing
 * needs to be guessed:
 *
 *   - hunk line counts, recounted from the lines actually present;
 *   - a missing file header, using the path the FINDING names (the pipeline has
 *     already established that the model's answer was about that file, so the
 *     patch's own paths carry no information worth trusting);
 *   - an empty line inside a hunk body, which is an empty context line that
 *     lost its single leading space to something in the model's formatting.
 *
 * Refused, because the correct value is NOT derivable and guessing is how a
 * patch silently edits the wrong thing: a body line that is not a diff line
 * (`...` where code was elided, a stray comment, prose). The failure is
 * reported with the line number and the text, so the developer can see what the
 * model tried to do.
 *
 * This is the fail-closed side of the policy in the file header of
 * hooks/pre-commit.ts: doubt about whether an edit will land correctly is
 * security-relevant, so it stops the apply rather than being smoothed over.
 */

import { parsePatch } from 'diff';

/** One hunk as the patch declares it, after counting has been corrected. */
export interface HunkRange {
  oldStart: number;
  oldLines: number;
  newStart: number;
  newLines: number;
}

export interface RepairedPatch {
  /** Exactly what the model returned, for the [v]iew option and reports. */
  original: string;
  /** A well-formed unified diff, ready for the applier. */
  text: string;
  /** What had to be fixed, in plain words. Empty when the patch was clean. */
  repairs: string[];
  /** Declared hunk ranges, so the applier can check where the edit landed. */
  hunks: HunkRange[];
}

export type PatchParseResult =
  | { ok: true; patch: RepairedPatch }
  | { ok: false; reason: string };

/** `@@ -old,oldLines +new,newLines @@`, with the counts optional. */
const HUNK_HEADER = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

/** One line, collapsed to something that fits in an error message. */
function glimpse(text: string, limit = 60): string {
  const shown = text.replace(/\s+/g, ' ').trim();
  if (shown === '') return '(an empty line)';
  return shown.length <= limit ? shown : `${shown.slice(0, limit - 1)}…`;
}

/**
 * Checks that a string is a patch the applier can actually use.
 *
 * Exists separately from {@link parseAndRepairPatch} because the [e]dit flow
 * needs to ask the same question about text a human typed, where there is
 * nothing to repair — the developer's version is authoritative, and silently
 * rewriting it would mean applying something they did not write. It is the same
 * check either way, so an edit is held to exactly the standard the model's
 * output is.
 */
export function validatePatch(text: string): { ok: true } | { ok: false; reason: string } {
  if (text.trim() === '') return { ok: false, reason: 'the patch is empty' };

  let parsed: ReturnType<typeof parsePatch>;
  try {
    parsed = parsePatch(text);
  } catch (error) {
    return { ok: false, reason: error instanceof Error ? error.message : String(error) };
  }

  const files = parsed.filter((entry) => (entry.hunks?.length ?? 0) > 0);
  if (files.length === 0) return { ok: false, reason: 'the patch contains no hunks' };
  if (files.length > 1) {
    // A suggested patch is a fix for one finding in one file. A multi-file
    // patch is either a model mistake or something that was pasted in, and
    // applying part of it would be worse than refusing all of it.
    return { ok: false, reason: `the patch describes ${files.length} files; expected one` };
  }

  return { ok: true };
}

/**
 * Takes a human-edited patch at its word.
 *
 * The [e]dit flow hands the developer the repaired diff — not the model's raw
 * text — so what they edit is already well-formed and their version is the
 * authoritative one. It is validated but never repaired: quietly rewriting
 * something a person typed and then saving it would mean applying an edit they
 * did not make, and if their version is broken the right answer is to say so and
 * let them fix it, not to fix it for them.
 */
export function adoptPatch(text: string, file: string): PatchParseResult {
  const valid = validatePatch(text);
  if (!valid.ok) return valid;

  // The hunks are re-read from the developer's text rather than carried over
  // from the model's, because their edit may have moved or resized them and the
  // placement check has to measure against what is actually about to be applied.
  const hunks: HunkRange[] = parsePatch(text).flatMap((entry) =>
    (entry.hunks ?? []).map((hunk) => ({
      oldStart: hunk.oldStart,
      oldLines: hunk.oldLines,
      newStart: hunk.newStart,
      newLines: hunk.newLines,
    })),
  );

  return { ok: true, patch: { original: text, text, repairs: [], hunks } };
}

/**
 * Repairs a model-written patch, then validates the result.
 *
 * @param raw  `suggested_patch` exactly as the provider returned it.
 * @param file Repo-relative path of the file the finding is in.
 */
export function parseAndRepairPatch(raw: string, file: string): PatchParseResult {
  const lines = raw.split(/\r?\n/);

  // Trailing blank lines are not part of any hunk, and a hunk body that ends
  // with one counts it as an empty context line — which would turn a patch that
  // is merely newline-terminated into a patch with a phantom extra line.
  while (lines.length > 0 && (lines.at(-1) ?? '').trim() === '') lines.pop();

  const firstHunk = lines.findIndex((line) => line.startsWith('@@'));
  if (firstHunk === -1) {
    return {
      ok: false,
      reason: 'the patch contains no hunk header — a suggested patch must include at least one line beginning with "@@"',
    };
  }

  const repairs: string[] = [];
  const declared = lines.slice(0, firstHunk).filter((line) => line.startsWith('--- '));
  const declaredHeader = declared[0];
  if (declaredHeader === undefined) {
    repairs.push(
      `added the missing file header (--- a/${file} / +++ b/${file}) — the patch began at its first hunk`,
    );
  } else if (declaredHeader.slice(4).trim() !== `a/${file}`) {
    // Worth saying out loud rather than quietly correcting: if the model named a
    // different file, the developer should know the patch was retargeted.
    repairs.push(
      `replaced the patch's file header (${glimpse(declaredHeader, 40)}) with the file the finding is in (${file})`,
    );
  }

  const body = lines.slice(firstHunk);
  const out: string[] = [`--- a/${file}`, `+++ b/${file}`];
  const hunks: HunkRange[] = [];

  let index = 0;
  let hunkNumber = 0;
  /**
   * 1-based line number within the patch as the provider wrote it.
   *
   * An error that says "line 4" has to mean line 4 of something the reader can
   * look at, and the body slice starts at the first `@@` — which is the whole
   * patch when the model omitted the header, and two lines in when it did not.
   */
  const at = (offset: number): number => firstHunk + offset + 1;

  while (index < body.length) {
    const header = body[index] ?? '';
    const match = HUNK_HEADER.exec(header);
    if (match === null) {
      return { ok: false, reason: `line ${at(index)} of the patch is not a valid @@ hunk header: ${glimpse(header)}` };
    }
    hunkNumber += 1;
    const oldStart = Number(match[1]);
    const newStart = Number(match[3]);
    index += 1;

    // Recount from the body. The header's own numbers are ignored entirely —
    // the body is the patch, and the counts are a claim about it that can be
    // checked rather than believed.
    let oldLines = 0;
    let newLines = 0;
    const bodyLines: string[] = [];
    while (index < body.length && !(body[index] ?? '').startsWith('@@')) {
      const line = body[index] ?? '';
      // An empty line in a body can only be an empty context line: the next
      // hunk starts with @@, and anything else is not a diff line at all. It
      // arrives empty because the model's formatting dropped the single leading
      // space that carries the "unchanged" marker.
      const operation = line === '' ? ' ' : line[0];
      if (operation === '+') newLines += 1;
      else if (operation === '-') oldLines += 1;
      else if (operation === ' ') {
        oldLines += 1;
        newLines += 1;
      } else if (operation === '\\') {
        // `\ No newline at end of file`. Carried through verbatim; it marks the
        // line before it and counts towards neither side. The marker is real —
        // parsePatch reads it — so dropping it would change what the patch says
        // about the file's final newline.
      } else {
        return {
          ok: false,
          reason:
            `line ${at(index)} of the patch is not a diff line, so CodeGuard will not guess what it ` +
            `replaces: ${glimpse(line)}`,
        };
      }
      bodyLines.push(line === '' ? ' ' : line);
      index += 1;
    }

    if (bodyLines.length === 0) {
      return { ok: false, reason: `hunk ${hunkNumber} has no content lines` };
    }

    const repairedHeader = `@@ -${oldStart},${oldLines} +${newStart},${newLines} @@`;
    if (repairedHeader !== header) {
      repairs.push(
        `hunk ${hunkNumber}'s header counted lines it does not have; recounted from its body as ` +
          `${oldLines} removed/context and ${newLines} added/context`,
      );
    }
    out.push(repairedHeader, ...bodyLines);
    hunks.push({ oldStart, oldLines, newStart, newLines });
  }

  const text = `${out.join('\n')}\n`;
  const valid = validatePatch(text);
  if (!valid.ok) {
    // Unreachable for anything this function built, and kept because the cost of
    // being wrong about that is a malformed patch reaching the applier.
    return { ok: false, reason: `the repaired patch is still not usable: ${valid.reason}` };
  }

  return { ok: true, patch: { original: raw, text, repairs, hunks } };
}
