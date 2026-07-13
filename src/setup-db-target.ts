import { auditMutating, confirmGate } from './audit.ts';
import { readTextOrEmpty, writeTextSecure } from './setup-file-io.ts';
import { buildSetupResult, type SetupResult } from './setup-types.ts';
import { defaultTargetsPath, loadTargets } from './targets.ts';

export interface ScaffoldOptions {
  alias: string;
  user: string;
  database: string;
  composeFile?: string;
  service?: string;
  container?: string;
  yes: boolean;
}

export interface ScaffoldData {
  name: string;
  alias: string;
  user: string;
  database: string;
  composeFile: string | null;
  service: string | null;
  container: string | null;
}

type ContainerRef =
  | { kind: 'compose'; composeFile: string; service: string }
  | { kind: 'container'; container: string }
  | { kind: 'invalid'; message: string };

/**
 * Mirrors `readTarget`'s own validation (`src/targets.ts:32-66`): exactly one of
 * `{compose_file, service}` or `{container}` — never both, never neither, never a partial
 * compose pair (compose_file without service, or vice versa).
 */
function resolveContainerRef(options: ScaffoldOptions): ContainerRef {
  const hasComposeFile = options.composeFile !== undefined;
  const hasService = options.service !== undefined;
  const hasContainer = options.container !== undefined;
  const hasCompose = hasComposeFile && hasService;

  if (hasCompose && hasContainer) {
    return {
      kind: 'invalid',
      message: 'declares both --compose-file/--service and --container — pick one',
    };
  }
  if (hasCompose) {
    return {
      kind: 'compose',
      composeFile: options.composeFile as string,
      service: options.service as string,
    };
  }
  if (hasContainer) {
    return { kind: 'container', container: options.container as string };
  }
  if (hasComposeFile !== hasService) {
    return { kind: 'invalid', message: '--compose-file and --service must be provided together' };
  }
  return { kind: 'invalid', message: 'needs either --compose-file/--service or --container' };
}

/** Field order/quoting matches targets.example.toml's per-field style. */
function buildTargetTableLines(
  name: string,
  options: ScaffoldOptions,
  ref: ContainerRef,
): string[] {
  const lines = [`[${name}]`, `alias = "${options.alias}"`];
  if (ref.kind === 'compose') {
    lines.push(`compose_file = "${ref.composeFile}"`, `service = "${ref.service}"`);
  } else if (ref.kind === 'container') {
    lines.push(`container = "${ref.container}"`);
  }
  lines.push(`user = "${options.user}"`, `database = "${options.database}"`);
  return lines;
}

/** Appends a blank-line-separated table after any existing content; the file always ends in
 *  exactly one trailing newline, mirroring setup-ssh-alias.ts's `appendStanza`. */
function appendTargetTable(existingText: string, tableLines: string[]): string {
  const trimmed = existingText.replace(/\s+$/, '');
  const tableText = tableLines.join('\n');
  return trimmed.length === 0 ? `${tableText}\n` : `${trimmed}\n\n${tableText}\n`;
}

/**
 * Appends a `[<name>]` table to `targets.toml`. Refuses with `VALIDATION_ERROR` if the
 * container reference isn't exactly one of `{compose_file, service}` or `{container}` —
 * checked before the `--yes` gate and before any file write, since it's a structural
 * argument error rather than a mutation the human might reasonably want to confirm. Refuses
 * with `TARGET_EXISTS` if `<name>` is already declared, leaving the existing file untouched.
 */
export function scaffold(
  name: string,
  options: ScaffoldOptions,
  path: string = defaultTargetsPath(),
): SetupResult<ScaffoldData> {
  const command = 'setup db-target scaffold';
  const argsSummary = {
    name,
    alias: options.alias,
    user: options.user,
    database: options.database,
    composeFile: options.composeFile ?? '',
    service: options.service ?? '',
    container: options.container ?? '',
  };

  const ref = resolveContainerRef(options);
  if (ref.kind === 'invalid') {
    auditMutating({ alias: options.alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: { code: 'VALIDATION_ERROR', message: `target '${name}' ${ref.message}` },
    });
  }

  if (!confirmGate({ mutating: true, yes: options.yes })) {
    auditMutating({ alias: options.alias, command, argsSummary, outcome: 'refused' });
    return buildSetupResult({
      command,
      error: { code: 'CONFIRMATION_REQUIRED', message: 'scaffold requires --yes' },
    });
  }

  const existingTargets = loadTargets(path);
  if (name in existingTargets) {
    auditMutating({ alias: options.alias, command, argsSummary, outcome: 'error' });
    return buildSetupResult({
      command,
      error: { code: 'TARGET_EXISTS', message: `target '${name}' already exists in ${path}` },
    });
  }

  const tableLines = buildTargetTableLines(name, options, ref);
  const newText = appendTargetTable(readTextOrEmpty(path), tableLines);
  writeTextSecure(path, newText);

  auditMutating({ alias: options.alias, command, argsSummary, outcome: 'ok' });
  return buildSetupResult({
    command,
    data: {
      name,
      alias: options.alias,
      user: options.user,
      database: options.database,
      composeFile: ref.kind === 'compose' ? ref.composeFile : null,
      service: ref.kind === 'compose' ? ref.service : null,
      container: ref.kind === 'container' ? ref.container : null,
    },
  });
}
