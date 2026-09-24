import { describe, expect, it } from '@jest/globals';

import { runLocalScan } from '../index';
import { newFileDiff } from './helpers';

/** Scans one line of code and returns the sorted ids of everything flagged. */
async function ruleIdsFor(path: string, code: string): Promise<string[]> {
  const findings = await runLocalScan(newFileDiff(path, code));
  return findings.map((finding) => finding.ruleId).sort();
}

describe('rule detection — true positives', () => {
  const cases: Array<{ name: string; path: string; code: string; expected: string[] }> = [
    {
      name: 'SQL by string concatenation (JS)',
      path: 'src/db.js',
      code: 'const sql = "SELECT id FROM users WHERE id = " + userId;',
      expected: ['sql-string-concatenation'],
    },
    {
      name: 'SQL by concatenation with an UPDATE verb',
      path: 'src/db.js',
      code: 'const sql = "UPDATE users SET role = " + role;',
      expected: ['sql-string-concatenation'],
    },
    {
      name: 'SQL by template-literal interpolation (JS)',
      path: 'src/db.js',
      code: "const sql = `SELECT * FROM orders WHERE status = '${status}'`;",
      expected: ['sql-template-interpolation'],
    },
    {
      name: 'SQL by f-string interpolation (Python)',
      path: 'app/db.py',
      code: 'query = f"SELECT id FROM users WHERE id = {user_id}"',
      expected: ['sql-fstring-interpolation'],
    },
    {
      name: 'SQL by %-formatting (Python)',
      path: 'app/db.py',
      code: 'query = "SELECT id FROM users WHERE id = %s" % user_id',
      expected: ['sql-percent-format'],
    },
    {
      name: 'SQL by str.format() (Python)',
      path: 'app/db.py',
      code: 'query = "SELECT id FROM users WHERE id = {}".format(user_id)',
      expected: ['sql-str-format'],
    },
    {
      name: 'credential assigned a literal (JS)',
      path: 'src/config.js',
      code: 'const apiKey = "sk_live_9f8a7b6c5d4e3f2a1b0c";',
      expected: ['hardcoded-secret-assignment'],
    },
    {
      name: 'credential assigned a literal (Python)',
      path: 'app/settings.py',
      code: 'DB_PASSWORD = "Spr1ng2024!prod"',
      expected: ['hardcoded-secret-assignment'],
    },
    {
      name: 'AWS access key id',
      path: 'src/aws.js',
      code: 'const key = "AKIAIOSFODNN7EXAMPLE";',
      expected: ['hardcoded-secret-aws-key'],
    },
    {
      name: 'private key block',
      path: 'deploy/id_rsa',
      code: '-----BEGIN RSA PRIVATE KEY-----',
      expected: ['hardcoded-secret-private-key'],
    },
    {
      name: 'strcpy in C',
      path: 'src/main.c',
      code: 'strcpy(dest, src);',
      expected: ['unsafe-c-strcpy'],
    },
    {
      name: 'gets in C',
      path: 'src/main.c',
      code: 'gets(buf);',
      expected: ['unsafe-c-gets'],
    },
    {
      name: 'sprintf in C',
      path: 'src/main.c',
      code: 'sprintf(buf, "%s", name);',
      expected: ['unsafe-c-sprintf'],
    },
    {
      name: 'system() in C',
      path: 'src/main.c',
      code: 'system(cmd);',
      expected: ['command-injection-system'],
    },
    {
      name: 'os.system() in Python',
      path: 'app/util.py',
      code: 'os.system("ls " + path)',
      expected: ['command-injection-system'],
    },
  ];

  it.each(cases)('flags $name', async ({ path, code, expected }) => {
    expect(await ruleIdsFor(path, code)).toEqual(expected);
  });
});

describe('rule detection — false positives must not fire', () => {
  const cases: Array<{ name: string; path: string; code: string }> = [
    {
      name: 'a parameterised query',
      path: 'src/db.js',
      code: "db.query('SELECT id FROM users WHERE id = ?', [id]);",
    },
    {
      name: 'a credential read from the environment',
      path: 'src/config.js',
      code: 'const apiKey = process.env.API_KEY;',
    },
    {
      name: 'the placeholder value "changeme"',
      path: 'app/settings.py',
      code: 'PASSWORD = "changeme"',
    },
    {
      name: 'a masked value',
      path: 'app/settings.py',
      code: 'PASSWORD = "xxxxxxxxxx"',
    },
    {
      name: 'a documentation slot',
      path: 'app/settings.py',
      code: 'API_KEY = "<YOUR_API_KEY>"',
    },
    {
      name: 'an unexpanded interpolation',
      path: 'app/settings.py',
      code: 'PASSWORD = "${DB_PASSWORD}"',
    },
    {
      name: 'a value too short to be a real credential',
      path: 'app/settings.py',
      code: 'PASSWORD = "abc"',
    },
    {
      name: 'snprintf (the bounded version of sprintf)',
      path: 'src/main.c',
      code: 'snprintf(buf, sizeof(buf), "%s", name);',
    },
    {
      name: 'fgets (the bounded version of gets)',
      path: 'src/main.c',
      code: 'fgets(buf, sizeof(buf), stdin);',
    },
    {
      name: 'strncpy (the bounded version of strcpy)',
      path: 'src/main.c',
      code: 'strncpy(dest, src, sizeof(dest) - 1);',
    },
    {
      name: 'an identifier that merely ends in "strcpy"',
      path: 'src/main.c',
      code: 'my_strcpy_wrapper(a, b, n);',
    },
    {
      name: 'an identifier that merely starts with "system"',
      path: 'src/main.c',
      code: 'system_utils_ready();',
    },
    {
      name: 'a C function name appearing in a JavaScript file',
      path: 'src/util.js',
      code: 'strcpy(dest, src);',
    },
    {
      name: 'a SQL statement with no concatenation',
      path: 'db/schema.sql',
      code: 'SELECT id FROM users WHERE id = 1;',
    },
    {
      name: 'a template literal with no SQL in it',
      path: 'src/greet.js',
      code: 'const msg = `Hello, ${name}!`;',
    },
    {
      name: 'an ordinary line of code',
      path: 'src/util.js',
      code: 'const total = items.reduce((sum, item) => sum + item.price, 0);',
    },
  ];

  it.each(cases)('does not flag $name', async ({ path, code }) => {
    expect(await ruleIdsFor(path, code)).toEqual([]);
  });
});

describe('documented limitation: a regex cannot tell code from a comment', () => {
  it('flags a dangerous call that appears only inside a comment', async () => {
    // Local Mode is pattern matching over single lines (PRD §6.2: "pattern-based
    // warnings only — no contextual reasoning"). Distinguishing code from
    // comments needs per-language parsing, which is out of scope here, and the
    // consequence is this false positive. The test asserts it deliberately so
    // the behaviour is a known property of the engine rather than a surprise,
    // and so that adding comment-awareness later has something to flip.
    expect(await ruleIdsFor('src/main.c', '// legacy: strcpy(dest, src);')).toEqual([
      'unsafe-c-strcpy',
    ]);
  });
});
