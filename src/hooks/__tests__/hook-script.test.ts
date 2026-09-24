import { spawnSync } from 'node:child_process';

import { describe, expect, it } from '@jest/globals';

import { BACKUP_SUFFIX, HOOK_MARKER, buildHookScript } from '../pre-commit';

/**
 * The generated hook is the one artefact of this feature that runs outside our
 * process, in a shell we do not control, at a moment the developer cannot
 * interrupt. It is worth asserting on its text directly.
 */
describe('buildHookScript', () => {
  const fresh = buildHookScript({ previousHookRelativePath: null, mechanism: 'native' });
  const wrapped = buildHookScript({
    previousHookRelativePath: `.git/hooks/pre-commit${BACKUP_SUFFIX}`,
    mechanism: 'native',
  });

  it('starts with a portable shebang', () => {
    expect(fresh.startsWith('#!/usr/bin/env sh\n')).toBe(true);
  });

  it('carries the marker that makes re-installation idempotent', () => {
    // installPreCommitHook greps for this string to distinguish "our hook, safe
    // to overwrite" from "somebody else's hook, preserve it".
    expect(fresh).toContain(HOOK_MARKER);
    expect(wrapped).toContain(HOOK_MARKER);
  });

  it('uses LF endings only', () => {
    // A carriage return inside the shebang line or a shell keyword makes the
    // script fail in ways that are painful to diagnose from a commit refusal.
    expect(fresh).not.toContain('\r');
    expect(wrapped).not.toContain('\r');
  });

  it('runs the scan against the staged diff', () => {
    expect(fresh).toContain('exec "$CODEGUARD" scan --staged');
  });

  it('resolves the CLI from CODEGUARD_BIN, then a local install, then PATH', () => {
    expect(fresh).toContain('CODEGUARD="${CODEGUARD_BIN:-}"');
    expect(fresh).toContain('./node_modules/.bin/codeguard');
    expect(fresh).toContain('CODEGUARD="codeguard"');
  });

  it('allows the commit, loudly, when the CLI cannot be found', () => {
    // Failing open here is the documented policy: an un-installed CLI must not
    // make a repository permanently un-committable, but it must not be silent.
    expect(fresh).toContain('command -v "$CODEGUARD"');
    expect(fresh).toContain('NO security check ran');
    expect(fresh).toMatch(/CodeGuard: executable not found[\s\S]*exit 0/);
  });

  it('mentions the escape hatch, so it is discovered by reading rather than by frustration', () => {
    expect(fresh).toContain('--no-verify');
  });

  it('omits the preserved-hook block when nothing was displaced', () => {
    expect(fresh).not.toContain('CODEGUARD_PREVIOUS');
  });

  it('runs a displaced hook first and honours its exit status', () => {
    expect(wrapped).toContain(`CODEGUARD_PREVIOUS=".git/hooks/pre-commit${BACKUP_SUFFIX}"`);
    // The preserved hook must run before the scan, so an existing gate keeps
    // its precedence, and its failure must stop the commit as it always did.
    // Compared against the exec line rather than the bare words "scan --staged",
    // which also appear in the explanatory header at the top of the script.
    expect(wrapped.indexOf('CODEGUARD_PREVIOUS')).toBeLessThan(
      wrapped.indexOf('exec "$CODEGUARD" scan --staged'),
    );
    expect(wrapped).toContain('"$CODEGUARD_PREVIOUS" "$@" || exit $?');
  });

  it('falls back to sh for a preserved hook that is not executable', () => {
    // Windows has no execute bit, and Git for Windows runs hooks regardless.
    // Without this branch a displaced hook would be skipped in silence there.
    expect(wrapped).toContain('sh "$CODEGUARD_PREVIOUS" "$@" || exit $?');
  });

  const SH_AVAILABLE = spawnSync('sh', ['-c', 'exit 0']).status === 0;
  const maybe = SH_AVAILABLE ? describe : describe.skip;

  maybe('generated shell syntax', () => {
    it.each([
      ['no preserved hook', fresh],
      ['with a preserved hook', wrapped],
    ])('parses as valid sh (%s)', (_name, script) => {
      // `sh -n` parses without executing. This is the cheapest possible guard
      // against shipping a hook that never runs.
      const result = spawnSync('sh', ['-n'], { input: script, encoding: 'utf8' });
      expect(result.stderr).toBe('');
      expect(result.status).toBe(0);
    });
  });
});
