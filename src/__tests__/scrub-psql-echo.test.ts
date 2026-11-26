import { describe, expect, test } from 'bun:test';
import { MASK, scrubText } from '../scrub.ts';

/** One psql error text per case, each quoting a row value the way psql 16 prints it (read off the
 *  fixture's postgres); the value must never survive, and the rest of the line must. */
const VALUE = 'Rk7pQ2vXw9LmZ4tH"quoted';
const DIGITS = '912345678901234567890';

const CASES: [string, string, string][] = [
  [
    'cast: invalid input syntax for type',
    `ERROR:  invalid input syntax for type integer: "${VALUE}"`,
    `ERROR:  invalid input syntax for type integer: "${MASK}"`,
  ],
  [
    'cast to a multi-word type',
    `ERROR:  invalid input syntax for type double precision: "${VALUE}"`,
    `ERROR:  invalid input syntax for type double precision: "${MASK}"`,
  ],
  [
    'enum cast: invalid input value for enum',
    `ERROR:  invalid input value for enum canary_mood: "${VALUE}"`,
    `ERROR:  invalid input value for enum canary_mood: "${MASK}"`,
  ],
  [
    'integer range: value "<v>" is out of range',
    `ERROR:  value "${DIGITS}" is out of range for type integer`,
    `ERROR:  value "${MASK}" is out of range for type integer`,
  ],
  [
    'float range: "<v>" is out of range, no value prefix',
    `ERROR:  "9e999" is out of range for type double precision`,
    `ERROR:  "${MASK}" is out of range for type double precision`,
  ],
  [
    'date range: date out of range',
    `ERROR:  date out of range: "${DIGITS}"`,
    `ERROR:  date out of range: "${MASK}"`,
  ],
  [
    'timestamp range: timestamp out of range',
    `ERROR:  timestamp out of range: "${DIGITS}"`,
    `ERROR:  timestamp out of range: "${MASK}"`,
  ],
  [
    'interval cast: interval field value out of range',
    `ERROR:  interval field value out of range: "${DIGITS}"`,
    `ERROR:  interval field value out of range: "${MASK}"`,
  ],
  [
    'array cast: malformed array literal',
    `ERROR:  malformed array literal: "${VALUE}"\nDETAIL:  Array value must start with "{" or dimension information.`,
    `ERROR:  malformed array literal: "${MASK}"\nDETAIL:  Array value must start with "{" or dimension information.`,
  ],
  [
    'date cast: date/time field value out of range',
    `ERROR:  date/time field value out of range: "${DIGITS}"`,
    `ERROR:  date/time field value out of range: "${MASK}"`,
  ],
  [
    'to_date: invalid value "<v>" for "<field>"',
    `ERROR:  invalid value "${VALUE}" for "Month"`,
    `ERROR:  invalid value "${MASK}" for "Month"`,
  ],
  [
    'json cast: Token DETAIL and JSON data CONTEXT',
    `DETAIL:  Token "${VALUE}" is invalid.\nCONTEXT:  JSON data, line 1: ${VALUE}`,
    `DETAIL:  Token "${MASK}" is invalid.\nCONTEXT:  JSON data, line 1: ${MASK}`,
  ],
  [
    'json cast: but found "<v>"',
    `DETAIL:  Expected ":", but found "${VALUE}".`,
    `DETAIL:  Expected ":", but found "${MASK}".`,
  ],
  [
    'unique violation DETAIL: Key (...)=(...) already exists',
    `DETAIL:  Key (email, password)=(ops@example.com, ${VALUE}) already exists.`,
    `DETAIL:  Key (email, password)=(${MASK}) already exists.`,
  ],
  [
    'foreign key DETAIL: is not present in table',
    `DETAIL:  Key (owner)=(${VALUE}) is not present in table "users".`,
    `DETAIL:  Key (owner)=(${MASK}) is not present in table "users".`,
  ],
  [
    'exclusion DETAIL: both keys',
    `DETAIL:  Key (slot)=(${VALUE}) conflicts with existing key (slot)=(${VALUE}).`,
    `DETAIL:  Key (slot)=(${MASK}) conflicts with existing key (slot)=(${MASK}).`,
  ],
  [
    'not-null / check DETAIL: Failing row contains',
    `DETAIL:  Failing row contains (1, null, ${VALUE}, ${DIGITS}).`,
    `DETAIL:  Failing row contains (${MASK}).`,
  ],
];

describe('scrubText — psql error texts that echo row data', () => {
  for (const [name, input, expected] of CASES) {
    test(name, () => {
      const result = scrubText(input);
      expect(result.value).toBe(expected);
      expect(result.count).toBeGreaterThan(0);
    });
  }

  test('a psql error that quotes no data is left whole', () => {
    for (const text of [
      'ERROR:  value too long for type character varying(3)',
      'ERROR:  column "nonexistent" does not exist',
      'ERROR:  invalid input syntax for type json',
    ]) {
      expect(scrubText(text)).toEqual({ value: text, count: 0 });
    }
  });

  test('an already-masked value is not counted twice', () => {
    const text = `ERROR:  invalid input syntax for type integer: "${MASK}"`;
    expect(scrubText(text)).toEqual({ value: text, count: 0 });
  });
});
