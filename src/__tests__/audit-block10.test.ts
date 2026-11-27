import { describe, expect, test } from 'bun:test';
import { classifySqlStatement, splitSqlStatements } from '../db.ts';

/**
 * Block 10 audit, phase 13: each test pins one receipt finding and is red at 80f7409. The db cases
 * are lexical (the classifier alone decides refusal before anything is sent). The phase 12 cases
 * live in audit-block10-exec.test.ts.
 */

const classify = (sql: string) => splitSqlStatements(sql).map(classifySqlStatement);

describe('P13-F1: the splitter and the server must agree on where a statement ends', () => {
  test('SET standard_conforming_strings is refused (it would let the server see a ; the splitter calls string)', () => {
    const infos = classify(
      "SET standard_conforming_strings = off;\nSELECT 'a\\''; DROP TABLE victim; --';\n",
    );
    const refusedOrDdl = infos.some((info) => info.refused !== null || info.ddl);
    expect(refusedOrDdl).toBe(true);
  });
});

describe('P13-F2: a quoted name is the same setting or function to Postgres', () => {
  for (const sql of [
    'SET "statement_timeout" = 0;',
    'SET "role" = postgres;',
    'SET SESSION "role" TO postgres;',
    'RESET "role";',
    'SET "standard_conforming_strings" = off;',
    "SELECT \"set_config\"('statement_timeout', '0', false);",
  ]) {
    test(`refused: ${sql}`, () => {
      expect(classify(sql)[0]?.refused).not.toBeNull();
    });
  }
});

describe('P13-F3: tables[] names tables, not keywords or CTE names', () => {
  test('MERGE ... UPDATE SET does not report a table called "set"', () => {
    const [info] = classify(
      'MERGE INTO t USING exec_demo s ON t.id = s.id WHEN MATCHED THEN UPDATE SET note = s.note;',
    );
    expect(info?.tables).not.toContain('set');
  });
  test('a CTE name is not a table', () => {
    const [info] = classify(
      "WITH d AS (DELETE FROM t RETURNING id) INSERT INTO exec_demo(note) SELECT 'z' FROM d;",
    );
    expect(info?.tables).not.toContain('d');
  });
  test('a table after a function in a FROM list is still reported', () => {
    const [info] = classify(
      "INSERT INTO exec_demo (note) SELECT 'g' FROM generate_series(1,2), t LIMIT 0;",
    );
    expect(info?.tables).toContain('t');
  });
});
