/**
 * Writing a repaired patch into the working tree.
 *
 * `applyPatch` does the actual editing. What this module adds is the part that
 * decides whether the result is trustworthy enough to write, because the
 * applier's guarantees are narrower than they look.
 *
 * ─── What applyPatch guarantees, verified against diff@9 ─────────────────────
 * It does NOT apply a hunk at the line number the header claims. It tries that
 * line first and, failing, scans outwards for a region whose context and deleted
 * lines match EXACTLY. A hunk with a completely wrong offset still applies, at
 * the right place, because the content is the real anchor. That is mostly good
 * news: the model's sloppy line numbers cannot misplace an edit.
 *
 * The exception is the one worth defending against. "Match exactly, anywhere"
 * means a file with two identical blocks can satisfy the wrong one, and the
 * written result is a real edit in the wrong place, staged, one keystroke from
 * being committed. So after applying, the changed region is checked against the
 * ranges the hunks declare — see {@link placementProblem}. The mood is the
 * fail-closed one from the file header of hooks/pre-commit.ts: doubt about
 * whether an edit landed correctly is security-relevant, so it stops the write
 * rather than being smoothed over.
 *
 * What none of this can check is whether the patch is CORRECT — a fix that is
 * exactly where it says it is can still be the wrong fix. That is what the
 * developer's review is for (FR-7), and it is why nothing here writes without
 * an explicit [a]pply.
 */

import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { applyPatch, diffLines } from 'diff';

import type { RepairedPatch } from './normalise';

export interface ApplyRequest {
  repoRoot: string;
  /** Repo-relative path of the file to edit, as the finding names it. */
  file: string;
  patch: RepairedPatch;
}

export interface AppliedPatch {
  /** The file's new contents, in the file's own line-ending style. */
  content: string;
  /** 1-based line numbers of `content` that differ from before. */
  changedLines: number[];
}

export type ApplyResult =
  | ({ ok: true } & AppliedPatch)
  | { ok: false; reason: string };

/**
 * The lines a patch would change, counted in the new file.
 *
 * Walks the line diff and tracks the position on the new side, so a removal is
 * attributed to the point where it was removed from. A removal at the end of a
 * hunk is therefore reported as the first line after it, which is why the
 * placement check below allows a hunk's range to extend one line past its
 * declared length rather than rejecting a deletion that sits at the boundary.
 */
function changedLineNumbers(source: string, content: string): number[] {
  const changed: number[] = [];
  let line = 1;

  for (const part of diffLines(source, content)) {
    const count = part.count ?? part.value.split('\n').length - (part.value.endsWith('\n') ? 1 : 0);
    if (part.added === true) {
      for (let offset = 0; offset < count; offset += 1) changed.push(line + offset);
      line += count;
    } else if (part.removed === true) {
      // A replacement arrives as a removal and an addition at the same
      // position, so both are recorded and the set below collapses them. A
      // removal with no addition keeps this single entry, which is the line the
      // text was removed from.
      changed.push(line);
    } else {
      line += count;
    }
  }

  return [...new Set(changed)].sort((a, b) => a - b);
}

/**
 * Whether the edited region lies inside the ranges the patch declared.
 *
 * Deliberately a BOUND rather than an exact fit. The hunk a patch declares
 * includes its context lines, and the model's context is typically three lines
 * either side, so an edit inside its own hunk has room to spare; what this
 * rejects is an edit that landed somewhere else entirely, which is the
 * duplicate-context case above.
 *
 * The one line of slack at each end is for removals, which `applyPatch` reports
 * as taking effect at a position rather than over a range.
 */
function placementProblem(changed: readonly number[], patch: RepairedPatch): string | null {
  for (const line of changed) {
    const inside = patch.hunks.some(
      (hunk) => line >= hunk.newStart - 1 && line <= hunk.newStart + Math.max(hunk.newLines, 1),
    );
    if (!inside) {
      const ranges = patch.hunks
        .map((hunk) => `${hunk.newStart}-${hunk.newStart + Math.max(hunk.newLines, 1) - 1}`)
        .join(', ');
      return (
        `the edit would land on line ${line}, outside every range the patch declares (${ranges}). ` +
        'The patch matched the file somewhere other than where it says it belongs, which usually ' +
        'means the file contains a near-identical block. CodeGuard did not write it.'
      );
    }
  }
  return null;
}

/**
 * Applies a repaired patch to text that is already newline-normalised.
 *
 * Pure and exported so the whole decision — does this apply, where did it land —
 * can be exercised without touching the filesystem.
 */
export function applyToText(source: string, patch: RepairedPatch): ApplyResult {
  const content = applyPatch(source, patch.text, { fuzzFactor: 0 });
  if (content === false) {
    return {
      ok: false,
      reason:
        'the patch does not fit this file. Either the file has changed since the scan, or the ' +
        'patch expects lines that are not there.',
    };
  }

  if (content === source) {
    // Parsed, fitted, and changed nothing. There is no such thing as a
    // suggested patch that is a no-op, so something above this layer is wrong
    // and writing the file would stage a change called "fixed" that fixes
    // nothing.
    return { ok: false, reason: 'the patch applied cleanly but changed nothing' };
  }

  const changedLines = changedLineNumbers(source, content);
  const problem = placementProblem(changedLines, patch);
  if (problem !== null) return { ok: false, reason: problem };

  return { ok: true, content, changedLines };
}

/** Whether the text uses only CRLF line endings, only LF, or both. */
function lineEndingStyle(text: string): 'crlf' | 'lf' | 'mixed' {
  const crlf = (text.match(/\r\n/g) ?? []).length;
  const lf = (text.match(/\n/g) ?? []).length;
  if (crlf === 0) return 'lf';
  return crlf === lf ? 'crlf' : 'mixed';
}

/** Resolves a repo-relative path, refusing anything that leaves the repository. */
function resolveInsideRepo(repoRoot: string, file: string): { ok: true; target: string } | { ok: false; reason: string } {
  const root = path.resolve(repoRoot);
  const target = path.resolve(root, file);
  const relative = path.relative(root, target);

  // The path comes from a finding, and the finding's file came from a parsed
  // diff rather than from the model's prose — but this is the write path, and
  // the cost of checking is one comparison against the cost of being wrong
  // about where a model-authored patch may write.
  if (relative === '' || relative.startsWith('..') || path.isAbsolute(relative)) {
    return { ok: false, reason: `${file} resolves outside the repository, so it will not be written` };
  }
  return { ok: true, target };
}

/**
 * Applies a repaired patch to a file, or explains why it did not.
 *
 * Line endings are converted to LF before applying and back afterwards. jsdiff
 * would do this itself (`autoConvertLineEndings`), but relying on that makes the
 * one thing that decides whether a patch matches — the exact bytes of each
 * line — a library default rather than something visible in this file.
 *
 * A file with MIXED endings is refused rather than normalised. Converting it
 * would rewrite every line, turning a three-line fix into a whole-file diff for
 * reasons that have nothing to do with the vulnerability.
 */
export async function applyPatchToFile(request: ApplyRequest): Promise<ApplyResult> {
  const resolved = resolveInsideRepo(request.repoRoot, request.file);
  if (!resolved.ok) return resolved;

  let onDisk: string;
  try {
    onDisk = await readFile(resolved.target, 'utf8');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    return {
      ok: false,
      reason:
        code === 'ENOENT'
          ? `${request.file} does not exist in the working tree`
          : `could not read ${request.file} — ${error instanceof Error ? error.message : String(error)}`,
    };
  }

  const style = lineEndingStyle(onDisk);
  if (style === 'mixed') {
    return {
      ok: false,
      reason:
        `${request.file} mixes LF and CRLF line endings, so CodeGuard will not rewrite it ` +
        'automatically — a three-line fix would become a whole-file diff. Apply this one by hand.',
    };
  }

  const applied = applyToText(style === 'crlf' ? onDisk.replace(/\r\n/g, '\n') : onDisk, request.patch);
  if (!applied.ok) return applied;

  const output = style === 'crlf' ? applied.content.replace(/\n/g, '\r\n') : applied.content;
  await writeFile(resolved.target, output, 'utf8');
  return applied;
}
