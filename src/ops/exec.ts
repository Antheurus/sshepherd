import { closeSync, constants, fstatSync, openSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, join } from 'node:path';
import { describeError } from '../errors.ts';
import {
  EXEC_MAX_ARGV_ITEMS,
  EXEC_MAX_DEF_FILE_BYTES,
  EXEC_MAX_DEFS,
  EXEC_MAX_PARAM_BYTES,
  EXEC_MAX_PARAMS,
  EXEC_TIMEOUT_SEC,
} from '../limits.ts';
import { arg, optStrOrNull, reqStr } from '../op-args.ts';
import { capLines, recountLines } from '../parsers/logs-shape.ts';
import { shellJoin, shellJoinExact, shq } from '../quote.ts';
import { maskPemBodyChunks, maskPemLines } from '../scrub.ts';
import { didYouMean } from '../suggest.ts';
import { declaredContainers } from '../targets.ts';
import { parseTomlFile } from '../toml-parse.ts';
import { type ErrorInfo, type OpContext, OpError, type OpSpec, Premasked } from '../types.ts';

/**
 * Named exec: the only way sshepherd runs a command the registry does not know, and only one a
 * human declared in `~/.config/sshepherd/exec/<alias>.toml` (0600, owned by the user). A definition
 * is an argv array, never a shell string; each `{param}` fills one whole argv element after its
 * value passed the universal gates (length, control characters, leading `-`, shell metacharacters,
 * a shell name) and its declared type. A `path` param is resolved by `realpath` on the host and must
 * still lie under its `under` root there, so a symlink cannot lead it out. Free text and scripts are
 * not accepted (plan assumption A2); `allow_shell = true` is the human's explicit opt-in for a def
 * whose argv names a shell.
 *
 * Two ops instead of one because a def's `mutating` decides the gate: `exec run` takes read-only
 * defs at the `read` profile with no `--yes`, `exec change` takes any def at `deploy` with `--yes`.
 * The CLI's `exec <alias> <name>` picks one from the def; `exec run` re-reads it and refuses a
 * mutating def, so a def edited between the two reads can only fail closed.
 */

type ParamType =
  | { type: 'enum'; values: string[] }
  | { type: 'int'; min: number; max: number }
  | { type: 'path'; under: string }
  | { type: 'regex'; pattern: RegExp; source: string }
  | { type: 'container' };

interface ParamDef {
  name: string;
  spec: ParamType;
  default: string | null;
}

export interface ExecDef {
  name: string;
  summary: string | null;
  argv: string[];
  mutating: boolean;
  container: string | null;
  allowShell: boolean;
  params: ParamDef[];
}

const DEF_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const PARAM_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,31}$/;
const CONTAINER_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const SLOT = /^\{([A-Za-z_][A-Za-z0-9_]{0,31})\}$/;
const DEF_KEYS = new Set(['summary', 'argv', 'mutating', 'container', 'allow_shell', 'params']);
const PARAM_KEYS: Record<ParamType['type'], string[]> = {
  enum: ['values'],
  int: ['min', 'max'],
  path: ['under'],
  regex: ['pattern'],
  container: [],
};

/** Program names that read their arguments as a script; argv naming one needs `allow_shell`. */
const SHELLS = new Set([
  'sh',
  'bash',
  'dash',
  'zsh',
  'ksh',
  'mksh',
  'ash',
  'yash',
  'fish',
  'csh',
  'tcsh',
  'busybox',
]);
/** Characters a remote shell (or a shell the command itself starts) gives meaning to. Quoting makes
 *  each harmless on sshepherd's own command line; refusing them keeps a value from becoming code
 *  in whatever the declared command hands it to next. */
const SHELL_METACHARS = /[;&|`$<>(){}[\]*?!~#'"\\]/;
/** A NUL, line break, tab, escape or any other C0 control character, or DEL. */
function hasControlChar(value: string): boolean {
  return [...value].some((char) => {
    const code = char.codePointAt(0) ?? 0;
    return code <= 0x1f || code === 0x7f;
  });
}

/** The remote guard's own exit status and markers: a `path` param that is missing on the host or
 *  resolves outside its root stops the script before the declared command starts. */
const GUARD_EXIT = 97;
const PATH_MISSING = '__SSHEPHERD_EXEC_PATH_MISSING__';
const PATH_ESCAPE = '__SSHEPHERD_EXEC_PATH_ESCAPE__';

/** Overridable via `SSHEPHERD_EXEC_DIR` for tests — mirrors targets.ts's SSHEPHERD_TARGETS_PATH. */
export function defaultExecDir(): string {
  const override = process.env.SSHEPHERD_EXEC_DIR;
  if (override && override.length > 0) {
    return override;
  }
  return join(homedir(), '.config', 'sshepherd', 'exec');
}

const fileLabel = (alias: string): string => `~/.config/sshepherd/exec/${alias}.toml`;
const defsHint = (alias: string): string =>
  `A human fixes ${fileLabel(alias)} (SSHEPHERD_EXEC_DIR overrides the directory); references/exec.md shows every field.`;

function defError(alias: string, message: string): OpError {
  return new OpError('CONFIG_PARSE_ERROR', `${fileLabel(alias)}: ${message}`, {
    hint: defsHint(alias),
  });
}

/** Opened without following a link and checked on the open descriptor, so the file whose owner and
 *  mode were checked is the file that is read. */
function readDefFile(alias: string): string {
  const path = join(defaultExecDir(), `${alias}.toml`);
  let fd: number;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (err) {
    const code = err instanceof Error && 'code' in err ? err.code : undefined;
    if (code === 'ENOENT') {
      throw new OpError('VALIDATION_ERROR', `no exec definitions for alias '${alias}'`, {
        hint: `A human declares the commands this alias may run in ${fileLabel(alias)} (chmod 600); references/exec.md shows the format.`,
      });
    }
    if (code === 'ELOOP') {
      throw new OpError('VALIDATION_ERROR', `${fileLabel(alias)} is a symbolic link`, {
        hint: `A human replaces the link with the file itself (chmod 600 ${fileLabel(alias)}); a link can be pointed elsewhere without touching the file it names.`,
      });
    }
    throw new OpError(
      'VALIDATION_ERROR',
      `${fileLabel(alias)} could not be opened (${String(code)})`,
      {
        hint: defsHint(alias),
      },
    );
  }
  try {
    const stat = fstatSync(fd);
    const uid = process.getuid?.();
    if (!stat.isFile()) {
      throw new OpError('VALIDATION_ERROR', `${fileLabel(alias)} is not a regular file`, {
        hint: defsHint(alias),
      });
    }
    if (uid !== undefined && stat.uid !== uid) {
      throw new OpError(
        'VALIDATION_ERROR',
        `${fileLabel(alias)} is not owned by the user running sshepherd`,
        {
          hint: `A human makes it theirs (chown "$USER" ${fileLabel(alias)}; chmod 600 ${fileLabel(alias)}); a definition another account can write is not one this user declared.`,
        },
      );
    }
    if ((stat.mode & 0o077) !== 0) {
      throw new OpError(
        'VALIDATION_ERROR',
        `${fileLabel(alias)} has mode ${(stat.mode & 0o777).toString(8)}; group and other must have no access`,
        { hint: `A human runs chmod 600 ${fileLabel(alias)}.` },
      );
    }
    if (stat.size > EXEC_MAX_DEF_FILE_BYTES) {
      throw defError(alias, `is ${stat.size} bytes; the limit is ${EXEC_MAX_DEF_FILE_BYTES}`);
    }
    return readFileSync(fd, 'utf8');
  } finally {
    closeSync(fd);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readParamType(alias: string, where: string, raw: Record<string, unknown>): ParamType {
  const type = raw.type;
  if (typeof type !== 'string' || !Object.hasOwn(PARAM_KEYS, type)) {
    throw defError(
      alias,
      `${where} has type ${JSON.stringify(type)}; expected one of ${Object.keys(PARAM_KEYS).join(', ')}`,
    );
  }
  const allowed = new Set(['type', 'default', ...(PARAM_KEYS[type as ParamType['type']] ?? [])]);
  const unknown = Object.keys(raw).filter((key) => !allowed.has(key));
  if (unknown.length > 0) {
    throw defError(alias, `${where} has unknown field(s) ${unknown.join(', ')} for type ${type}`);
  }
  if (type === 'enum') {
    const values = raw.values;
    if (
      !Array.isArray(values) ||
      values.length === 0 ||
      values.some((value) => typeof value !== 'string' || value.length === 0)
    ) {
      throw defError(alias, `${where}.values must be a non-empty list of non-empty strings`);
    }
    return { type, values: values as string[] };
  }
  if (type === 'int') {
    const { min, max } = raw;
    if (
      typeof min !== 'number' ||
      typeof max !== 'number' ||
      !Number.isSafeInteger(min) ||
      !Number.isSafeInteger(max) ||
      min < 0 ||
      min > max
    ) {
      throw defError(alias, `${where} needs whole numbers 0 <= min <= max`);
    }
    return { type, min, max };
  }
  if (type === 'path') {
    const under = raw.under;
    if (
      typeof under !== 'string' ||
      !under.startsWith('/') ||
      under === '/' ||
      under.split('/').some((part) => part === '..' || part === '.') ||
      hasControlChar(under)
    ) {
      throw defError(
        alias,
        `${where}.under must be an absolute directory other than / with no . or .. segment`,
      );
    }
    return { type, under: under.replace(/\/+$/, '') };
  }
  if (type === 'regex') {
    const source = raw.pattern;
    if (typeof source !== 'string' || source.length === 0) {
      throw defError(alias, `${where}.pattern must be a non-empty regular expression`);
    }
    try {
      return { type, pattern: new RegExp(`^(?:${source})$`, 'u'), source };
    } catch {
      throw defError(alias, `${where}.pattern is not a valid regular expression`);
    }
  }
  return { type: 'container' };
}

function readParams(alias: string, defName: string, raw: unknown): ParamDef[] {
  if (raw === undefined) {
    return [];
  }
  if (!isRecord(raw)) {
    throw defError(alias, `[${defName}.params] must be a table of param tables`);
  }
  const names = Object.keys(raw).sort();
  if (names.length > EXEC_MAX_PARAMS) {
    throw defError(
      alias,
      `[${defName}] declares ${names.length} params; the limit is ${EXEC_MAX_PARAMS}`,
    );
  }
  return names.map((name) => {
    const where = `[${defName}.params.${name}]`;
    const entry = raw[name];
    if (!PARAM_NAME.test(name) || !isRecord(entry)) {
      throw defError(alias, `${where} must be a table named with letters, digits and _`);
    }
    const spec = readParamType(alias, where, entry);
    const fallback = entry.default;
    if (fallback !== undefined && typeof fallback !== 'string' && typeof fallback !== 'number') {
      throw defError(alias, `${where}.default must be a string or a number`);
    }
    return { name, spec, default: fallback === undefined ? null : String(fallback) };
  });
}

function readDef(alias: string, name: string, raw: unknown): ExecDef {
  if (!DEF_NAME.test(name) || !isRecord(raw)) {
    throw defError(
      alias,
      `[${name}] must be a table named with letters, digits, _ and - (at most 64 characters)`,
    );
  }
  const unknown = Object.keys(raw).filter((key) => !DEF_KEYS.has(key));
  if (unknown.length > 0) {
    throw defError(alias, `[${name}] has unknown field(s) ${unknown.join(', ')}`);
  }
  const { argv, mutating, container, summary } = raw;
  if (
    !Array.isArray(argv) ||
    argv.length === 0 ||
    argv.length > EXEC_MAX_ARGV_ITEMS ||
    argv.some((item) => typeof item !== 'string' || item.length === 0 || item.includes('\0'))
  ) {
    throw defError(
      alias,
      `[${name}].argv must be a list of 1-${EXEC_MAX_ARGV_ITEMS} non-empty strings (an argv array, never one shell string)`,
    );
  }
  if (typeof mutating !== 'boolean') {
    throw defError(alias, `[${name}].mutating must be true or false — it decides the --yes gate`);
  }
  if (
    container !== undefined &&
    (typeof container !== 'string' || !CONTAINER_NAME.test(container))
  ) {
    throw defError(alias, `[${name}].container must be a container name`);
  }
  if (summary !== undefined && typeof summary !== 'string') {
    throw defError(alias, `[${name}].summary must be a string`);
  }
  if (raw.allow_shell !== undefined && typeof raw.allow_shell !== 'boolean') {
    throw defError(alias, `[${name}].allow_shell must be true or false`);
  }
  const params = readParams(alias, name, raw.params);
  const declared = new Set(params.map((param) => param.name));
  const items = argv as string[];
  if (SLOT.test(items[0] ?? '')) {
    throw defError(alias, `[${name}].argv[0] must be a literal program, not a param`);
  }
  const used = new Set<string>();
  for (const item of items) {
    const slot = SLOT.exec(item)?.[1];
    if (slot !== undefined) {
      if (!declared.has(slot)) {
        throw defError(
          alias,
          `[${name}].argv uses {${slot}}, which [${name}.params] does not declare`,
        );
      }
      used.add(slot);
      continue;
    }
    const spliced = [...declared].find((param) => item.includes(`{${param}}`));
    if (spliced !== undefined) {
      throw defError(
        alias,
        `[${name}].argv element ${JSON.stringify(item)} splices {${spliced}} into a larger string; a param fills one whole argv element`,
      );
    }
  }
  const unused = [...declared].filter((param) => !used.has(param));
  if (unused.length > 0) {
    throw defError(alias, `[${name}] declares param(s) ${unused.join(', ')} that argv never uses`);
  }
  return {
    name,
    summary: typeof summary === 'string' ? summary : null,
    argv: items,
    mutating,
    container: typeof container === 'string' ? container : null,
    allowShell: raw.allow_shell === true,
    params,
  };
}

/** Every definition of the alias, read and checked whole on each call: one malformed entry stops
 *  them all, since a file the human got wrong somewhere is not a file whose intent can be trusted. */
export function loadExecDefs(alias: string): ExecDef[] {
  const raw = parseTomlFile(readDefFile(alias), fileLabel(alias), defsHint(alias));
  const names = Object.keys(raw).sort();
  if (names.length > EXEC_MAX_DEFS) {
    throw defError(alias, `holds ${names.length} definitions; the limit is ${EXEC_MAX_DEFS}`);
  }
  const defs = names.map((name) => readDef(alias, name, raw[name]));
  for (const def of defs) {
    for (const param of def.params) {
      if (param.default !== null) {
        try {
          checkValue(def, param, param.default, alias);
        } catch (err) {
          throw defError(
            alias,
            `[${def.name}.params.${param.name}].default is refused: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }
    }
  }
  return defs;
}

function findDef(alias: string, name: string): ExecDef {
  const defs = loadExecDefs(alias);
  const def = defs.find((entry) => entry.name === name);
  if (def === undefined) {
    throw new OpError('VALIDATION_ERROR', `'${name}' is not declared in ${fileLabel(alias)}`, {
      hint: 'Use a declared name; a human adds new ones to the file.',
      next: `sshepherd exec list ${alias}`,
      did_you_mean: didYouMean(
        name,
        defs.map((entry) => entry.name),
      ),
    });
  }
  return def;
}

/** For the CLI's `exec <alias> <name>`: whether the def asks for `exec change`. Any failure answers
 *  no, so the call goes to `exec run`, which re-reads the def and reports the real problem. */
export function execDefIsMutating(alias: string, name: string): boolean {
  try {
    return findDef(alias, name).mutating;
  } catch {
    return false;
  }
}

function badValue(param: string, problem: string, hint: string): OpError {
  return new OpError('INVALID_ARGS', `--param ${param}: ${problem}`, { hint });
}

function checkPath(param: ParamDef, under: string, value: string): void {
  const refuse = (problem: string): never => {
    throw new OpError('VALIDATION_ERROR', `--param ${param.name}: ${problem}`, {
      hint: `Pass an absolute path under ${under} with no . or .. segment.`,
    });
  };
  if (!value.startsWith('/')) {
    refuse('the path must be absolute');
  }
  if (value.split('/').some((part) => part === '..' || part === '.')) {
    refuse('the path must not contain a . or .. segment');
  }
  if (value !== under && !value.startsWith(`${under}/`)) {
    refuse(`the path is outside ${under}`);
  }
}

/** The universal gates every value passes, then its declared type. */
function checkValue(def: ExecDef, param: ParamDef, value: string, alias: string): void {
  const name = param.name;
  const bytes = Buffer.byteLength(value, 'utf8');
  if (bytes === 0) {
    throw badValue(name, 'the value is empty', 'Pass name=value with a non-empty value.');
  }
  if (bytes > EXEC_MAX_PARAM_BYTES) {
    throw badValue(
      name,
      `the value is ${bytes} bytes; the limit is ${EXEC_MAX_PARAM_BYTES}`,
      `Shorten it to at most ${EXEC_MAX_PARAM_BYTES} bytes.`,
    );
  }
  if (hasControlChar(value)) {
    throw badValue(
      name,
      'the value contains a NUL, line break or other control character',
      'Pass the value on one line with printable characters only.',
    );
  }
  if (value.startsWith('-')) {
    throw badValue(
      name,
      "the value starts with '-', so the command would read it as an option",
      'Pass a value that does not start with -.',
    );
  }
  if (SHELL_METACHARS.test(value)) {
    throw badValue(
      name,
      'the value contains a shell metacharacter',
      'Values may not contain ; & | ` $ < > ( ) { } [ ] * ? ! ~ # quotes or backslash.',
    );
  }
  if (!def.allowShell && SHELLS.has(basename(value))) {
    throw badValue(
      name,
      `the value names a shell (${basename(value)})`,
      'Only a definition with allow_shell = true may be handed a shell.',
    );
  }
  const spec = param.spec;
  if (spec.type === 'enum' && !spec.values.includes(value)) {
    throw new OpError(
      'INVALID_ARGS',
      `--param ${name}: '${value}' is not one of the declared values`,
      {
        hint: `Use one of: ${spec.values.join(', ')}.`,
        did_you_mean: didYouMean(value, spec.values),
      },
    );
  }
  if (spec.type === 'int') {
    const number = /^\d{1,15}$/.test(value) ? Number(value) : Number.NaN;
    if (!(number >= spec.min && number <= spec.max)) {
      throw badValue(
        name,
        `'${value}' is not a whole number from ${spec.min} to ${spec.max}`,
        `Pass a whole number from ${spec.min} to ${spec.max}.`,
      );
    }
  }
  if (spec.type === 'regex' && !spec.pattern.test(value)) {
    throw badValue(
      name,
      'the value does not match the declared pattern',
      `The definition accepts values matching ${spec.source}.`,
    );
  }
  if (spec.type === 'container') {
    const declared = declaredContainers(alias);
    if (!declared.includes(value)) {
      throw new OpError(
        'INVALID_ARGS',
        `--param ${name}: container '${value}' is not declared for alias '${alias}' in targets.toml`,
        {
          hint: 'A human lists it in containers = [...] on a targets.toml entry for this alias; the agent never widens its own list.',
          did_you_mean: didYouMean(value, declared),
        },
      );
    }
  }
  if (spec.type === 'path') {
    checkPath(param, spec.under, value);
  }
}

/** `--param` arrives as a JSON list of `name=value` strings (the CLI packs every repeated flag). */
function readParamValues(ctx: OpContext, def: ExecDef, alias: string): Map<string, string> {
  const raw = optStrOrNull(ctx, 'param');
  let given: unknown = [];
  if (raw !== null) {
    try {
      given = JSON.parse(raw);
    } catch {
      given = null;
    }
  }
  if (!Array.isArray(given) || given.some((item) => typeof item !== 'string')) {
    throw new OpError('INVALID_ARGS', '--param must be name=value', {
      hint: 'Pass one --param name=value per param.',
    });
  }
  const pairs = given as string[];
  if (pairs.length > EXEC_MAX_PARAMS) {
    throw new OpError(
      'INVALID_ARGS',
      `${pairs.length} --param values given; the limit is ${EXEC_MAX_PARAMS}`,
      { hint: `A definition takes at most ${EXEC_MAX_PARAMS} params.` },
    );
  }
  const declared = def.params.map((param) => param.name);
  const values = new Map<string, string>();
  for (const pair of pairs) {
    const at = pair.indexOf('=');
    const name = at < 0 ? pair : pair.slice(0, at);
    if (at < 0 || !PARAM_NAME.test(name)) {
      throw new OpError('INVALID_ARGS', '--param must be name=value', {
        hint: `Pass one --param name=value per param; '${def.name}' takes ${declared.join(', ') || 'none'}.`,
      });
    }
    if (!declared.includes(name)) {
      throw new OpError('INVALID_ARGS', `'${def.name}' declares no param '${name}'`, {
        hint: `'${def.name}' takes ${declared.join(', ') || 'no params'}.`,
        did_you_mean: didYouMean(name, declared),
      });
    }
    if (values.has(name)) {
      throw new OpError('INVALID_ARGS', `--param ${name} is given twice`, {
        hint: 'Pass each param once.',
      });
    }
    values.set(name, pair.slice(at + 1));
  }
  for (const param of def.params) {
    const value = values.get(param.name) ?? param.default;
    if (value === null) {
      throw new OpError('INVALID_ARGS', `'${def.name}' needs --param ${param.name}=<value>`, {
        hint: `'${def.name}' takes ${declared.join(', ')}; see sshepherd exec list ${alias}.`,
      });
    }
    checkValue(def, param, value, alias);
    values.set(param.name, value);
  }
  return values;
}

function checkPolicy(def: ExecDef, alias: string): void {
  if (!def.allowShell) {
    const shell = def.argv.find((item) => !SLOT.test(item) && SHELLS.has(basename(item)));
    if (shell !== undefined) {
      throw new OpError(
        'VALIDATION_ERROR',
        `'${def.name}' runs a shell (${basename(shell)}) without allow_shell = true`,
        {
          hint: `A human either declares the program itself as argv[0], or sets allow_shell = true on [${def.name}] in ${fileLabel(alias)} after reading what the script does.`,
        },
      );
    }
  }
  if (def.container !== null && !declaredContainers(alias).includes(def.container)) {
    throw new OpError(
      'VALIDATION_ERROR',
      `'${def.name}' runs in container '${def.container}', which is not declared for alias '${alias}' in targets.toml`,
      {
        hint: 'A human lists it in containers = [...] on a targets.toml entry for this alias; the agent never widens its own list.',
      },
    );
  }
}

/** The remote command: the declared argv (inside `docker exec <container>` when the def names one),
 *  each slot its validated value as one quoted word. A `path` slot is first resolved on the host —
 *  where the command runs, so inside the container too — and the command gets the resolved path. */
function execRemote(def: ExecDef, values: Map<string, string>): string {
  const prefix = def.container === null ? [] : ['docker', 'exec', def.container];
  const pathParams = def.params.filter((param) => param.spec.type === 'path');
  if (pathParams.length === 0) {
    return shellJoinExact([
      ...prefix,
      ...def.argv.map((item) => {
        const slot = SLOT.exec(item)?.[1];
        return slot === undefined ? item : (values.get(slot) ?? '');
      }),
    ]);
  }
  const run = prefix.length === 0 ? '' : `${shellJoinExact(prefix)} `;
  const lines: string[] = [];
  pathParams.forEach((param, index) => {
    const under = param.spec.type === 'path' ? param.spec.under : '';
    const fail = (marker: string): string =>
      `{ echo ${marker} ${shq(param.name)} >&2; exit ${GUARD_EXIT}; }`;
    lines.push(
      `p${index}=${shq(values.get(param.name) ?? '')}`,
      `${run}test -e "$p${index}" || ${fail(PATH_MISSING)}`,
      `r${index}=$(${run}realpath -- "$p${index}") || ${fail(PATH_MISSING)}`,
      `u${index}=$(${run}realpath -- ${shq(under)}) || ${fail(PATH_MISSING)}`,
      `case "$r${index}" in "$u${index}"|"$u${index}"/*) ;; *) ${fail(PATH_ESCAPE)} ;; esac`,
    );
  });
  const words = def.argv.map((item) => {
    const slot = SLOT.exec(item)?.[1];
    if (slot === undefined) {
      return shq(item);
    }
    const index = pathParams.findIndex((param) => param.name === slot);
    return index < 0 ? shq(values.get(slot) ?? '') : `"$r${index}"`;
  });
  lines.push(`exec ${run}${words.join(' ')}`);
  return shellJoin(['sh', '-c', lines.join('\n')]);
}

function buildExec(ctx: OpContext, command: 'run' | 'change'): string {
  const name = reqStr(ctx, 'name');
  const def = findDef(ctx.alias, name);
  if (command === 'run' && def.mutating) {
    throw new OpError(
      'VALIDATION_ERROR',
      `'${name}' is declared mutating = true, so exec run will not start it`,
      {
        hint: 'A mutating definition runs through exec change with --yes (profile deploy or admin).',
        next: `sshepherd exec change ${ctx.alias} ${name}${def.params.length > 0 ? ' --param <name=value>' : ''} --yes`,
      },
    );
  }
  checkPolicy(def, ctx.alias);
  return execRemote(def, readParamValues(ctx, def, ctx.alias));
}

/** The guard's refusal, read off its marker: the path never reached the declared command. */
function refineGuardError(commandStderr: string, error: ErrorInfo): ErrorInfo | undefined {
  if (error.remote_exit !== GUARD_EXIT) {
    return undefined;
  }
  const missing = new RegExp(`${PATH_MISSING} (\\S+)`).exec(commandStderr)?.[1];
  const escaped = new RegExp(`${PATH_ESCAPE} (\\S+)`).exec(commandStderr)?.[1];
  if (escaped !== undefined) {
    return describeError(
      'VALIDATION_ERROR',
      `--param ${escaped}: the path resolves outside its declared root on the host (a symbolic link leads out); the command did not run`,
      { hint: 'Pass a path whose real location is under the root; a link out of it is refused.' },
    );
  }
  if (missing !== undefined) {
    return describeError(
      'VALIDATION_ERROR',
      `--param ${missing}: the path (or its root) does not exist on the host; the command did not run`,
      { hint: 'Pass a path that exists; list the directory with files ls if it is allowlisted.' },
    );
  }
  return undefined;
}

interface ExecResult {
  name: string;
  lines: string[];
  lines_returned: number;
}

function shapeExec(parsed: unknown, ctx: OpContext): Premasked<ExecResult> {
  const raw = String(parsed).split('\n');
  while (raw.length > 0 && raw[raw.length - 1]?.trimEnd() === '') {
    raw.pop();
  }
  const unmasked = raw.map((line) => line.trimEnd());
  const lines = maskPemBodyChunks(maskPemLines(unmasked));
  const masked = lines.filter((line, index) => line !== unmasked[index]).length;
  return new Premasked({ name: reqStr(ctx, 'name'), lines, lines_returned: lines.length }, masked);
}

const NAME_ARG = arg(
  'name',
  'positional',
  true,
  'Definition name, declared in ~/.config/sshepherd/exec/<alias>.toml (see exec list).',
);
const PARAM_ARG = arg(
  'param',
  'flag',
  false,
  `name=value for one declared param; repeat per param (at most ${EXEC_MAX_PARAMS}, ${EXEC_MAX_PARAM_BYTES} bytes each).`,
);

const execRun: OpSpec<ExecResult> = {
  group: 'exec',
  name: 'run',
  summary:
    'Run a declared read-only command (mutating = false) from exec/<alias>.toml; output scrubbed.',
  args: [NAME_ARG, PARAM_ARG],
  mutating: false,
  exposes: 'content',
  maskEnvBlocks: true,
  timeoutSec: EXEC_TIMEOUT_SEC,
  output: 'raw',
  capLines,
  recount: recountLines,
  buildRemote: (ctx) => buildExec(ctx, 'run'),
  shape: shapeExec,
  refineError: refineGuardError,
};

const execChange: OpSpec<ExecResult> = {
  group: 'exec',
  name: 'change',
  summary:
    'Run a declared command that changes the host (mutating = true); needs --yes, output scrubbed, audited.',
  args: [NAME_ARG, PARAM_ARG],
  mutating: true,
  exposes: 'content',
  maskEnvBlocks: true,
  timeoutSec: EXEC_TIMEOUT_SEC,
  truncateKeeps: 'tail',
  output: 'raw',
  capLines,
  recount: recountLines,
  buildRemote: (ctx) => buildExec(ctx, 'change'),
  shape: shapeExec,
  refineError: refineGuardError,
};

interface ExecListEntry {
  name: string;
  summary: string | null;
  mutating: boolean;
  runs_with: 'exec run' | 'exec change';
  container: string | null;
  allow_shell: boolean;
  argv: string[];
  params: Array<Record<string, unknown>>;
}

function describeParam(param: ParamDef): Record<string, unknown> {
  const spec = param.spec;
  const fields: Record<string, unknown> =
    spec.type === 'enum'
      ? { values: spec.values }
      : spec.type === 'int'
        ? { min: spec.min, max: spec.max }
        : spec.type === 'path'
          ? { under: spec.under }
          : spec.type === 'regex'
            ? { pattern: spec.source }
            : {};
  return { name: param.name, type: spec.type, ...fields, default: param.default };
}

const execList: OpSpec<{ defs: ExecListEntry[] }> = {
  group: 'exec',
  name: 'list',
  summary: 'List the commands declared for an alias, their params and whether they mutate.',
  args: [],
  mutating: false,
  exposes: 'none',
  timeoutSec: EXEC_TIMEOUT_SEC,
  output: 'raw',
  buildRemote: () => null,
  runLocal: (ctx) => ({
    defs: loadExecDefs(ctx.alias).map((def) => ({
      name: def.name,
      summary: def.summary,
      mutating: def.mutating,
      runs_with: def.mutating ? 'exec change' : 'exec run',
      container: def.container,
      allow_shell: def.allowShell,
      argv: def.argv,
      params: def.params.map(describeParam),
    })),
  }),
  shape: (parsed) => parsed as { defs: ExecListEntry[] },
};

export const execOps: OpSpec[] = [execRun as OpSpec, execChange as OpSpec, execList as OpSpec];
