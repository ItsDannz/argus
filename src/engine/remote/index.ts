/**
 * Remote AI Mode — two-stage DeepSeek pipeline (FR-3..FR-6, PRD §6.1).
 *
 * Stage 1: triage the whole diff with reasoning OFF  -> ScanFinding[]
 * Stage 2: deep-analyse + patch only flagged hunks, reasoning ON -> PatchSuggestion[]
 *
 * Phase 1 scaffold only. The live API integration lands in Phase 4, along with
 * the secret-redaction pass required by PRD §9.3 / NFR §8.
 */

import type { PatchSuggestion, ScanFinding } from '../../prompts/security-agent-prompts';

/**
 * Stage 1 — fast triage over the full diff.
 *
 * @param diff Unified diff. Callers must have already run the redaction pass.
 */
export async function runRemoteScan(_diff: string): Promise<ScanFinding[]> {
  throw new Error('runRemoteScan: Remote AI Mode is not implemented yet (Phase 4).');
}

/**
 * Stage 2 — deep analysis and patch generation for a single flagged finding.
 *
 * @param finding The triage-stage finding to confirm, reject, or patch.
 * @param hunk    The flagged hunk, plus optional surrounding context.
 */
export async function runRemotePatch(
  _finding: ScanFinding,
  _hunk: { hunk: string; surroundingContext?: string },
): Promise<PatchSuggestion> {
  throw new Error('runRemotePatch: Remote AI Mode is not implemented yet (Phase 4).');
}
