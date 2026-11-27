import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { listOps } from './registry.ts';
import type { SetupErrorInfo, SetupResult } from './setup-types.ts';
import type { Envelope, ErrorInfo, OpSpec } from './types.ts';

export type JsonSchema = Record<string, unknown>;

const DRAFT = 'https://json-schema.org/draft/2020-12/schema';

/** One entry per `ErrorInfo` field: adding a field to the type fails the typecheck until it is
 *  described here, and the snapshot test then fails until `bun run gen-schema` is committed. */
const ERROR_FIELDS: Record<keyof ErrorInfo, JsonSchema> = {
  code: { type: 'string', description: 'Stable error code; see SshErrorCode in src/types.ts.' },
  message: { type: 'string' },
  hint: { type: 'string', description: 'One sentence on what to do about this code.' },
  retryable: { type: 'boolean' },
  next: {
    type: 'string',
    description: 'An exact, runnable command that moves the caller forward.',
  },
  did_you_mean: { type: 'array', items: { type: 'string' } },
  remote_exit: { type: 'integer' },
  phase: { enum: ['connect', 'command'] },
  timeout_sec: { type: 'integer' },
  budget_sec: { type: 'integer' },
  elapsed_ms: { type: 'integer' },
  op_outcome: { enum: ['ok', 'error', 'refused'] },
  op_error: { type: 'object', description: 'AUDIT_WRITE_FAILED only: the op error, same shape.' },
  stderr_tail: {
    type: 'string',
    description: 'Last lines of the remote command stderr, scrubbed.',
  },
  data: { type: 'object', description: 'Structured detail an op recovered from the failure.' },
};

/** One entry per `Envelope` field, with the same completeness guarantee as `ERROR_FIELDS`. */
const ENVELOPE_FIELDS: Record<keyof Envelope<unknown>, JsonSchema> = {
  schema_version: { const: 1, description: 'Fields are only ever added within a version.' },
  ok: { type: 'boolean' },
  alias: { type: 'string' },
  ran_at: { type: 'string', format: 'date-time' },
  command: { type: 'string' },
  duration_ms: { type: 'integer' },
  scrubbed: { type: 'integer', description: 'How many values the scrubber masked.' },
  data: {},
  error: { anyOf: [{ type: 'null' }, { type: 'object', properties: ERROR_FIELDS }] },
  output_truncated: {
    const: true,
    description: 'Present only when output was cut by a byte or item cap.',
  },
  fields_unmatched: {
    type: 'array',
    items: { type: 'string' },
    description: '--fields paths that matched nothing.',
  },
  warnings: {
    type: 'array',
    items: {
      type: 'object',
      properties: {
        code: { const: 'AUDIT_UNWRITABLE' },
        message: { type: 'string' },
        hint: { type: 'string' },
        path_role: { enum: ['state_dir', 'audit_archive', 'audit_file'] },
        errno: { type: 'string' },
      },
    },
    description: 'Present only when something beside the op failed; the op result still stands.',
  },
};

const REQUIRED_ENVELOPE_FIELDS = [
  'schema_version',
  'ok',
  'alias',
  'ran_at',
  'command',
  'duration_ms',
  'scrubbed',
  'data',
  'error',
];

/** `setup *` prints its own result shape (no alias, no duration); same completeness guarantee. */
const SETUP_ERROR_FIELDS: Record<keyof SetupErrorInfo, JsonSchema> = {
  code: {
    type: 'string',
    description: 'Stable setup error code; see SetupErrorCode in src/setup-types.ts.',
  },
  message: { type: 'string' },
  hint: { type: 'string' },
  retryable: { type: 'boolean' },
  next: { type: 'string' },
  did_you_mean: { type: 'array', items: { type: 'string' } },
};

const SETUP_FIELDS: Record<keyof SetupResult<unknown>, JsonSchema> = {
  schema_version: ENVELOPE_FIELDS.schema_version,
  ok: { type: 'boolean' },
  command: { type: 'string' },
  ran_at: { type: 'string', format: 'date-time' },
  data: {},
  error: { anyOf: [{ type: 'null' }, { type: 'object', properties: SETUP_ERROR_FIELDS }] },
};

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The structure of a sample value: types and keys, never the values themselves. */
export function inferSchema(value: unknown): JsonSchema {
  if (value === null) {
    return { type: 'null' };
  }
  if (Array.isArray(value)) {
    const items = value
      .map(inferSchema)
      .reduce<JsonSchema | null>(
        (merged, next) => (merged === null ? next : mergeSchemas(merged, next)),
        null,
      );
    return items === null ? { type: 'array' } : { type: 'array', items };
  }
  if (isPlainObject(value)) {
    const properties: Record<string, JsonSchema> = {};
    for (const key of Object.keys(value).sort()) {
      properties[key] = inferSchema(value[key]);
    }
    return { type: 'object', properties };
  }
  if (typeof value === 'number') {
    return { type: Number.isInteger(value) ? 'integer' : 'number' };
  }
  return { type: typeof value };
}

function typesOf(schema: JsonSchema): string[] {
  const type = schema.type;
  return Array.isArray(type) ? (type as string[]) : typeof type === 'string' ? [type] : [];
}

/** The union of two inferred schemas: shared keys are merged, differing types become a type list. */
export function mergeSchemas(a: JsonSchema, b: JsonSchema): JsonSchema {
  if (JSON.stringify(a) === JSON.stringify(b)) {
    return a;
  }
  if (a.type === 'object' && b.type === 'object') {
    const left = (a.properties ?? {}) as Record<string, JsonSchema>;
    const right = (b.properties ?? {}) as Record<string, JsonSchema>;
    const properties: Record<string, JsonSchema> = {};
    for (const key of [...new Set([...Object.keys(left), ...Object.keys(right)])].sort()) {
      const l = left[key];
      const r = right[key];
      properties[key] = l !== undefined && r !== undefined ? mergeSchemas(l, r) : (l ?? r ?? {});
    }
    return { type: 'object', properties };
  }
  if (a.type === 'array' && b.type === 'array') {
    const items =
      a.items !== undefined && b.items !== undefined
        ? mergeSchemas(a.items as JsonSchema, b.items as JsonSchema)
        : (a.items ?? b.items);
    return items === undefined ? { type: 'array' } : { type: 'array', items };
  }
  const types = [...new Set([...typesOf(a), ...typesOf(b)])].sort();
  return types.length > 0 &&
    !('properties' in a) &&
    !('properties' in b) &&
    !('items' in a) &&
    !('items' in b)
    ? { type: types.length === 1 ? types[0] : types }
    : { anyOf: [a, b] };
}

/** Samples of `data` per command from recorded live runs (`ok` envelopes only), merged. */
export function dataShapesFromFixtures(fixtureDirs: string[]): Map<string, JsonSchema> {
  const shapes = new Map<string, JsonSchema>();
  for (const dir of fixtureDirs) {
    if (!existsSync(dir)) {
      continue;
    }
    for (const name of readdirSync(dir)
      .filter((file) => file.endsWith('.json'))
      .sort()) {
      const envelope = JSON.parse(readFileSync(join(dir, name), 'utf8')) as Partial<
        Envelope<unknown>
      >;
      if (
        envelope.ok !== true ||
        envelope.data === null ||
        envelope.data === undefined ||
        !envelope.command
      ) {
        continue;
      }
      const shape = inferSchema(envelope.data);
      const known = shapes.get(envelope.command);
      shapes.set(envelope.command, known === undefined ? shape : mergeSchemas(known, shape));
    }
  }
  return shapes;
}

function envelopeProperties(): Record<string, JsonSchema> {
  return { ...ENVELOPE_FIELDS };
}

export function buildEnvelopeSchema(): JsonSchema {
  return {
    $schema: DRAFT,
    $id: 'sshepherd/envelope',
    title: 'sshepherd envelope',
    description:
      'Every invocation prints one of these. Additions are non-breaking within schema_version 1.',
    type: 'object',
    required: REQUIRED_ENVELOPE_FIELDS,
    properties: envelopeProperties(),
    additionalProperties: true,
  };
}

export function buildSetupSchema(): JsonSchema {
  return {
    $schema: DRAFT,
    $id: 'sshepherd/setup',
    title: 'sshepherd setup result',
    description:
      'What every `setup` action prints, instead of the op envelope. Additions are non-breaking within schema_version 1.',
    type: 'object',
    required: Object.keys(SETUP_FIELDS),
    properties: { ...SETUP_FIELDS },
    additionalProperties: true,
  };
}

export function buildOpSchema(op: OpSpec, dataShape: JsonSchema | undefined): JsonSchema {
  const properties = envelopeProperties();
  properties.command = { const: `${op.group} ${op.name}` };
  properties.data = dataShape === undefined ? {} : { anyOf: [{ type: 'null' }, dataShape] };
  return {
    $schema: DRAFT,
    $id: `sshepherd/${op.group}-${op.name}`,
    title: `sshepherd ${op.group} ${op.name}`,
    description: op.summary,
    'x-sshepherd': {
      group: op.group,
      action: op.name,
      mutating: op.mutating,
      exposes: op.exposes,
      timeout_sec: op.timeoutSec,
      data_shape: dataShape === undefined ? 'unrecorded' : 'recorded',
      args: op.args.map((arg) => ({ name: arg.name, kind: arg.kind, required: arg.required })),
    },
    type: 'object',
    required: REQUIRED_ENVELOPE_FIELDS,
    properties,
    additionalProperties: true,
  };
}

/** file name -> pretty JSON text, for `envelope.json`, `setup.json` and one file per registry op. */
export function generateSchemas(fixtureDirs: string[]): Map<string, string> {
  const shapes = dataShapesFromFixtures(fixtureDirs);
  const files = new Map<string, string>();
  files.set('envelope.json', `${JSON.stringify(buildEnvelopeSchema(), null, 2)}\n`);
  files.set('setup.json', `${JSON.stringify(buildSetupSchema(), null, 2)}\n`);
  for (const op of listOps()) {
    const schema = buildOpSchema(op, shapes.get(`${op.group} ${op.name}`));
    files.set(`${op.group}-${op.name}.json`, `${JSON.stringify(schema, null, 2)}\n`);
  }
  return files;
}
