import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { scrubText } from '../scrub.ts';

const REPO = join(import.meta.dir, '..', '..');

describe('R07n operator-signature keep: a quoted regoper input never carries data', () => {
  test('a double-quoted "type op <hex>" value from ::regoper is masked in sql_error (no prefix)', () => {
    const value = `"integer = x${'53435241'.repeat(7)} x${'4d2d5348'.repeat(7)}"`;
    const out = scrubText(`operator does not exist: ${value}`).value;
    expect(out).not.toContain('53435241');
    expect(out).not.toContain('4d2d5348');
  });

  test('green guard: a real operator signature keeps its operand types', () => {
    expect(scrubText('operator does not exist: integer = text').value).toBe(
      'operator does not exist: integer = text',
    );
    expect(scrubText('operator does not exist: character varying[] @> integer').value).toContain(
      'character varying[]',
    );
  });
});

describe('R07n AUTH-named keys: a mechanism word is not a credential', () => {
  for (const text of ['SMTP_AUTH=login', 'auth: none', '{"auth": false}', 'redis.auth=on']) {
    test(`${text} stays readable`, () => {
      expect(scrubText(text).value).toBe(text);
    });
  }

  test('green guard: docker config.json auth blob stays masked', () => {
    const blob = Buffer.from('deploy:Zq8xLmT4vB9nRk2sWp7yHc3d').toString('base64');
    expect(scrubText(`{"auths":{"r.example":{"auth":"${blob}"}}}`).value).not.toContain(blob);
  });
});

describe('R07n MISMATCH wording matches the branch the code takes', () => {
  test('SKILL.md MISMATCH row does not say known_hosts holds no stale key (the code returns MISMATCH with one present)', () => {
    const row =
      readFileSync(join(REPO, 'SKILL.md'), 'utf8')
        .split('\n')
        .find((line) => line.startsWith('| `HOST_KEY_FINGERPRINT_MISMATCH`')) ?? '';
    expect(row).not.toContain('holds no key the host stopped presenting');
  });
});
