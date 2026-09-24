/**
 * Types for the Local Static Engine (PRD §6.2, FR-8).
 *
 * The Local Engine is detection-only: it can say "this line looks like a raw SQL
 * query" but never proposes a fix. That is why the finding shape deliberately
 * has no `suggested_patch` field — auto-patching is a Remote Mode capability
 * only.
 *
 * The shape itself now lives in `engine/findings.ts`, because Remote Mode
 * produces the same five fields and everything downstream — the threshold, the
 * report renderer, the future patch flow — has to accept both engines' output
 * without a branch. `LocalFinding` stays as the name this engine's callers
 * already use, so the move cost no import churn.
 */

export type { Finding, Finding as LocalFinding } from '../findings';
