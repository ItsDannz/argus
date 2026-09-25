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

describe('redactDiff — lines the Local Engine reported', () => {
  const SHORT_PASSWORD = '  dbPassword: "Spr1ng2024!prod",';

  it('withholds a value every heuristic walks past', () => {
    const diff = diffOf([SHORT_PASSWORD]);
    const known = [{ file: 'src/config.ts', line: 1 }];

    // The premise, so this test cannot quietly stop testing anything: without
    // the finding, the value goes out as written.
    expect(redactDiff(diff).diff).toContain('Spr1ng2024!prod');

    const { diff: redacted, redactions } = redactDiff(diff, known);
    expect(redacted).toContain('dbPassword: "«REDACTED:known-secret»"');
    expect(redacted).not.toContain('Spr1ng2024!prod');
    expect(redactions).toEqual([{ file: 'src/config.ts', label: 'known-secret' }]);
  });

  it('withholds the whole line when the value cannot be located within it', () => {
    // A shape the rules currently do not produce, so the fallback is ready
    // before it is needed. The engine said there is a credential on this line;
    // failing to put a finger on it is not a reason to send the line.
    const diff = diffOf(['  CREDENTIALS = base64("Zm9vYmFyYmF6cXV4");']);
    const { diff: redacted } = redactDiff(diff, [{ file: 'src/config.ts', line: 1 }]);

    expect(redacted).toContain('«REDACTED:known-secret»');
    expect(redacted).not.toContain('Zm9vYmFyYmF6cXV4');
  });

  it('redacts the flagged line in a CRLF diff', () => {
    // A diff from a Windows checkout. `parseDiff` strips the carriage return
    // when it records content; this module splits on `'\n'` and keeps it, so a
    // comparison that did not account for it would match nothing — and a silent
    // miss here is a credential on the wire.
    const diff = diffOf([SHORT_PASSWORD]).replace(/\n/g, '\r\n');

    const { diff: redacted } = redactDiff(diff, [{ file: 'src/config.ts', line: 1 }]);

    expect(redacted).not.toContain('Spr1ng2024!prod');
    // The line count is preserved here as everywhere: shape unchanged, `\r`
    // included, so the model's line ranges still point at the same code.
    expect(redacted.split('\n')).toHaveLength(diff.split('\n').length);
  });

  it('leaves a line it was not told about alone', () => {
    // The scope check. Only `hardcoded_secret` findings cross into this module,
    // and a line that carries no finding is none of its business — a redactor
    // that widened itself to every line would take the SQL out of the SQL
    // injection the model is being asked to reason about.
    const lines = ['  dbPassword: "Spr1ng2024!prod",', '  const q = sql + userId;'];
    const { diff: redacted, redactions } = redactDiff(diffOf(lines), [{ file: 'src/config.ts', line: 1 }]);

    expect(redactions).toHaveLength(1);
    expect(redacted).toContain('const q = sql + userId;');
  });

  it('keeps the label of a recogniser that got there first', () => {
    // An AWS key id on a line the rules also report. Both layers reach it; the
    // specific label is the one the developer should see, and the value is only
    // withheld once.
    const line = '  awsAccessKeyId: "AKIAIOSFODNN7EXAMPLE",';
    const { diff: redacted, redactions } = redactDiff(diffOf([line]), [{ file: 'src/config.ts', line: 1 }]);

    expect(redacted).toContain('«REDACTED:aws-access-key»');
    expect(redacted).not.toContain('known-secret');
    expect(redactions).toHaveLength(1);
  });

  it('ignores a finding that names a line the diff does not have', () => {
    // The model answers by line number and the rules report by line number, so a
    // number that resolves to nothing has to be a no-op rather than an error or
    // — worse — a wildcard that redacts the file.
    const diff = diffOf([SHORT_PASSWORD]);
    const { diff: redacted, redactions } = redactDiff(diff, [
      { file: 'src/config.ts', line: 99 },
      { file: 'src/other.ts', line: 1 },
    ]);

    expect(redactions).toEqual([]);
    expect(redacted).toBe(diff);
  });
});

/**
 * The invariant that ties the two secret-handling modules together: anything
 * the Local Engine is confident enough to REPORT must also be withheld from the
 * API.
 *
 * It used to hold only by luck of the sample list — which is the failure mode
 * this block is now shaped to prevent. Two layers make it true by construction:
 * the pattern list below catches most of these on their own, and the findings
 * themselves are passed to `redactDiff` so a line the rules named is withheld
 * whatever its shape. `dbPassword:` is the sample that proves the second layer
 * is load-bearing rather than decorative: the rule matches it (the credential
 * name is a substring, no word boundary required), while every heuristic here
 * walks past it (`\bpassword\b` does not match inside `dbPassword`, and 15
 * characters is under the backstop's floor).
 */
describe('detection implies redaction', () => {
  const SECRET_SAMPLES = [
    'const apiKey = "abcdef1234567890abcdef";',
    'const awsKey = "AKIAIOSFODNN7EXAMPLE";',
    'password: "correcthorsebatterystaple"',
    'clientSecret = "s3cr3t-v4lu3-that-is-long";',
    'authToken: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"',
    // The one the heuristics miss on their own. Prefix on the identifier, and a
    // value short enough to look like a password a person might have chosen.
    '  dbPassword: "Spr1ng2024!prod",',
  ];

  it('redacts every line the hardcoded-secret rules would report', async () => {
    const diff = diffOf(SECRET_SAMPLES);
    const findings = await runLocalScan(diff);
    const secretFindings = findings.filter((finding) => finding.ruleId.startsWith('hardcoded-secret'));

    // Guard against the test silently passing because nothing was detected.
    expect(secretFindings.length).toBeGreaterThan(0);
    // And the sample that motivates the floor is among them, so this test cannot
    // go on passing if the rule stops matching it for an unrelated reason.
    expect(secretFindings.map((finding) => finding.line)).toContain(6);

    const { diff: redacted } = redactDiff(diff, secretFindings);
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

/**
 * The residual: what redaction still cannot see.
 *
 * Recorded here as a boundary rather than left to be rediscovered. With the
 * rule engine's findings layered in, what remains is structural — redaction is
 * pattern matching, and a credential that matches no published shape, sits on no
 * line a rule recognises, and is too short for the entropy backstop is a
 * credential no amount of tuning this file will find. The fix for that is not a
 * lower floor (which swaps one arbitrary number for another and starts eating
 * lockfiles); it is the developer not committing the value.
 */
describe('the residual', () => {
  it('still transmits a secret that no rule and no pattern recognises', async () => {
    const line = 'const DATABASE_URL = "pg-super-secret-99";';
    const diff = diffOf([line]);

    // No rule names it: nothing credential-shaped precedes the `=`. (The word
    // `secret` appears only inside the value, where the rules do not look.)
    expect(await runLocalScan(diff)).toEqual([]);

    // And no pattern takes it: 18 characters is under the entropy backstop's
    // 20-character floor, so even with the context word present it survives.
    const { diff: redacted, redactions } = redactDiff(diff, []);
    expect(redactions).toEqual([]);
    expect(redacted).toContain('pg-super-secret-99');
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
