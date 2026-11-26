import { describe, expect, test } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { errorInfo } from '../errors.ts';
import { buildEnvelope } from '../output.ts';
import { listOps } from '../registry.ts';
import { generateSchemas, inferSchema, mergeSchemas } from '../schema.ts';

const ROOT = join(import.meta.dir, '..', '..');
const SCHEMA_DIR = join(ROOT, 'docs', 'schema');
const FIXTURE_DIRS = ['debian', 'alpine'].map((variant) =>
  join(import.meta.dir, 'fixtures', 'live', variant),
);

describe('docs/schema snapshot', () => {
  const generated = generateSchemas(FIXTURE_DIRS);

  test('every generated schema equals the committed file; run `bun run gen-schema` to announce a change', () => {
    for (const [name, text] of generated) {
      expect({ file: name, text: readFileSync(join(SCHEMA_DIR, name), 'utf8') }).toEqual({
        file: name,
        text,
      });
    }
  });

  test('docs/schema holds exactly the generated files, no orphan from a removed op', () => {
    expect(readdirSync(SCHEMA_DIR).sort()).toEqual([...generated.keys()].sort());
  });

  test('there is one schema per registry op plus the envelope and the setup result', () => {
    expect(generated.size).toBe(listOps().length + 2);
  });

  test('a real envelope carries only fields the envelope schema declares, with schema_version 1', () => {
    const envelope = buildEnvelope({
      alias: 'a',
      command: 'hosts test',
      startedAtMs: Date.now(),
      data: null,
      error: errorInfo('COMMAND_FAILED', 3),
    });
    const schema = JSON.parse(generated.get('envelope.json') ?? '{}') as {
      properties: Record<string, unknown>;
      required: string[];
    };
    expect(Object.keys(envelope).filter((key) => !(key in schema.properties))).toEqual([]);
    expect(schema.required.filter((key) => !(key in envelope))).toEqual([]);
    expect(envelope.schema_version).toBe(1);
  });
});

describe('inferSchema / mergeSchemas', () => {
  test('records types and keys, never values', () => {
    expect(inferSchema({ b: 'secret', a: [1, 2.5] })).toEqual({
      type: 'object',
      properties: {
        a: { type: 'array', items: { type: ['integer', 'number'] } },
        b: { type: 'string' },
      },
    });
  });

  test('merging a null with a string makes the string nullable', () => {
    expect(mergeSchemas({ type: 'null' }, { type: 'string' })).toEqual({
      type: ['null', 'string'],
    });
  });
});
