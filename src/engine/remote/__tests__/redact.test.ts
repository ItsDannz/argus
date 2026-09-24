import { describe, expect, it } from '@jest/globals';

import { runLocalScan } from '../../local';
import { redactApiKey, redactDiff } from '../redact';

/** Builds a one-file diff so redaction can be exercised on realistic input. */
function diffOf(lines: string[], path = 'src/config.ts'): string {
  return [
    `diff --git a/${path} b/${path}`,
    '--- a/' + path,
    '+++ b/' + path,
    `@@ -1,${lines.length} +1,${lines.length} @@`,
    ...lines.map((line) => `+${line}`),
    '',
  ].join('\n');
}

describe('redactDiff', () => {
  it('redacts credentials with recognisable shapes', () => {
    const cases: [string, string][] = [
      ['const id = "AKIAIOSFODNN7EXAMPLE";', 'aws-access-key'],
      ['token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";', 'github-token'],
      ['const s = "xoxb-123456789012-abcdefghijklmnop";', 'slack-token'],
      ['key = "sk-proj-abcdefghijklmnopqrstuvwxyz012345";', 'openai-key'],
      ['const g = "AIzaSyA1234567890abcdefghijklmnopqrstuv";', 'google-api-key'],
      ['npm_token = "npm_abcdefghijklmnopqrstuvwxyz0123456789";', 'npm-token'],
      [
        'const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g";',
        'jwt',
      ],
    ];

    for (const [line, label] of cases) {
      const { diff, redactions } = redactDiff(diffOf([line]));
      expect(diff).not.toContain('REDACTED_MISSING');
      expect(diff).toContain(`«REDACTED:${label}»`);
      expect(redactions.map((entry) => entry.label)).toContain(label);
    }
  });

  it('keeps the identifier that names a secret, and removes only the value', () => {
    // The model needs the identifier to judge what the line was doing. Matching
    // the whole `apiKey = "..."` expression would have removed both.
    const { diff } = redactDiff(diffOf(['const apiKey = "abcdef1234567890abcdef";']));
    expect(diff).toContain('const apiKey = "«REDACTED:assigned-secret»"');
  });

  it('keeps the scheme and host of a credential-bearing URL', () => {
    const { diff } = redactDiff(diffOf(['db = "postgres://admin:hunter2hunter2@db.internal:5432/app"']));
    expect(diff).toContain('postgres://«REDACTED:credential-in-url»@db.internal:5432/app');
  });

  it('redacts a whole private key block', () => {
    const pem = [
      '-----BEGIN RSA PRIVATE KEY-----',
      'MIIEowIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz',
      '-----END RSA PRIVATE KEY-----',
    ];
    const { diff, redactions } = redactDiff(diffOf(pem));
    expect(diff).toContain('«REDACTED:private-key»');
    expect(diff).not.toContain('MIIEowIBAAKCAQEA');
    expect(redactions).toHaveLength(1);
  });

  it('catches an unrecognised credential on a line that names one', () => {
    // Hex and lowercase base64 are the shapes a three-character-class rule
    // walks straight past. The value sits behind a call rather than directly
    // after the identifier, so only the entropy backstop can reach it.
    const { diff } = redactDiff(
      diffOf(['const token = load("9f8e7d6c5b4a39281706f5e4d3c2b1a0");']),
    );
    expect(diff).toContain('«REDACTED:high-entropy-value»');
  });

  it('keeps the most specific label when two patterns match the same value', () => {
    // `token = "ghp_..."` is both a GitHub token and a value assigned to an
    // identifier called `token`. The specific answer is the useful one, and the
    // generic pattern must not overwrite it.
    const { diff } = redactDiff(diffOf(['token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";']));
    expect(diff).toContain('«REDACTED:github-token»');
  });

  it('preserves the line count exactly', () => {
    // Invariant 1: the model's line_ranges are matched back to hunks, so a
    // redaction that added or removed a line would point them at wrong code.
    const lines = [
      'const apiKey = "abcdef1234567890abcdef";',
      'const normal = 1;',
      'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";',
    ];
    const input = diffOf(lines);
    const { diff } = redactDiff(input);
    expect(diff.split('\n')).toHaveLength(input.split('\n').length);
  });

  it('leaves ordinary code untouched', () => {
    const lines = [
      'export function add(a: number, b: number): number {',
      '  return a + b;',
      '}',
      'const timeoutMs = 30000;',
      'const url = "https://api.example.com/v1/users";',
    ];
    const { diff, redactions } = redactDiff(diffOf(lines));
    expect(redactions).toEqual([]);
    expect(diff).toBe(diffOf(lines));
  });

  it('does not gut a lockfile full of integrity hashes', () => {
    // The reason the heuristic needs a secret-naming word on the same line:
    // redacting every long random string would destroy the diff the model is
    // meant to reason about, while protecting nothing at all.
    const lines = [
      '    "integrity": "sha512-9f8e7d6c5b4a39281706f5e4d3c2b1a0f9e8d7c6b5a4938271605f4e3d2c1b0a",',
      '    "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.0.0.tgz",',
      '    "shasum": "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",',
    ];
    const { diff, redactions } = redactDiff(diffOf(lines, 'package-lock.json'));
    expect(redactions).toEqual([]);
    expect(diff).toBe(diffOf(lines, 'package-lock.json'));
  });

  it('does not redact the placeholder it just inserted', () => {
    const { diff, redactions } = redactDiff(diffOf(['const apiKey = "abcdef1234567890abcdef";']));
    expect(redactions).toHaveLength(1);
    expect(diff.match(/«REDACTED:/g)).toHaveLength(1);
  });

  it('reports the file, and never the value', () => {
    const { redactions } = redactDiff(diffOf(['const apiKey = "abcdef1234567890abcdef";'], 'src/db.ts'));
    expect(redactions).toEqual([{ file: 'src/db.ts', label: 'assigned-secret' }]);
    // FR-10's reasoning generalised: the value must not survive anywhere in
    // what we hand back, including the report.
    expect(JSON.stringify(redactions)).not.toContain('abcdef1234567890abcdef');
  });

  it('leaves hunk and diff headers byte-identical', () => {
    const input = diffOf(['const apiKey = "abcdef1234567890abcdef";']);
    const { diff } = redactDiff(input);
    const headers = (text: string): string[] =>
      text.split('\n').filter((line) => line.startsWith('@@') || line.startsWith('diff --git'));
    expect(headers(diff)).toEqual(headers(input));
  });
});

/**
 * The invariant that ties the two secret-handling modules together: anything
 * the Local Engine is confident enough to REPORT must also be withheld from the
 * API. Detection and redaction are tuned differently on purpose, so this is the
 * check that the recall-oriented list is genuinely a superset in practice.
 */
describe('detection implies redaction', () => {
  const SECRET_SAMPLES = [
    'const apiKey = "abcdef1234567890abcdef";',
    'const awsKey = "AKIAIOSFODNN7EXAMPLE";',
    'password: "correcthorsebatterystaple"',
    'clientSecret = "s3cr3t-v4lu3-that-is-long";',
    'authToken: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"',
  ];

  it('redacts every line the hardcoded-secret rules would report', async () => {
    const diff = diffOf(SECRET_SAMPLES);
    const findings = await runLocalScan(diff);
    const secretFindings = findings.filter((finding) => finding.ruleId.startsWith('hardcoded-secret'));

    // Guard against the test silently passing because nothing was detected.
    expect(secretFindings.length).toBeGreaterThan(0);

    const { diff: redacted } = redactDiff(diff);
    // `newLine` counts added lines, so index into the added lines only — and
    // exclude the `+++ b/...` header, which also starts with "+".
    const addedLines = redacted
      .split('\n')
      .filter((line) => line.startsWith('+') && !line.startsWith('+++ '));

    for (const finding of secretFindings) {
      expect(addedLines[finding.line - 1]).toContain('«REDACTED:');
    }
  });
});

describe('redactApiKey', () => {
  it('removes the key from arbitrary text', () => {
    const text = 'request failed: Authorization: Bearer sk-abc123456789';
    expect(redactApiKey(text, 'sk-abc123456789')).toContain('«REDACTED:api-key»');
    expect(redactApiKey(text, 'sk-abc123456789')).not.toContain('sk-abc123456789');
  });

  it('removes every occurrence, not just the first', () => {
    expect(redactApiKey('a KEY b KEY', 'KEY')).toBe('a «REDACTED:api-key» b «REDACTED:api-key»');
  });

  it('returns the text unchanged when there is no key', () => {
    expect(redactApiKey('nothing to do', null)).toBe('nothing to do');
    expect(redactApiKey('nothing to do', '')).toBe('nothing to do');
  });
});
