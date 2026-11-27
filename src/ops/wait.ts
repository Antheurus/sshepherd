import { describeError } from '../errors.ts';
import {
  MAX_WAIT_PATTERN_CHARS,
  WAIT_DEFAULT_TIMEOUT_SEC,
  WAIT_MAX_TIMEOUT_SEC,
  WAIT_MIN_TIMEOUT_SEC,
  WAIT_POLL_INTERVAL_SEC,
  WAIT_REPLY_GRACE_SEC,
  WAIT_URL_PROBE_TIMEOUT_SEC,
} from '../limits.ts';
import { arg, assertPositional, optStrOrNull, reqStr } from '../op-args.ts';
import { shellJoin, shq } from '../quote.ts';
import { httpStatusCommand } from '../recipes.ts';
import { type ErrorInfo, type OpContext, OpError, type OpSpec, type RawResult } from '../types.ts';
import { localUrl } from './http.ts';

type Condition =
  | { kind: 'healthy'; container: string }
  | { kind: 'log-contains'; pattern: string; container: string }
  | { kind: 'port-open'; port: number }
  | { kind: 'url'; url: string; status: string };

const CONTAINER_SUFFIX = '@container=';
const STATUS_SUFFIX = ':status=';
const CONDITION_FORMS =
  'healthy@container=NAME, log-contains:<regex>@container=NAME, port-open:<port>, url:<localhost-url>[:status=<code>]';

function badCondition(message: string): OpError {
  return new OpError('INVALID_ARGS', `wait for: ${message}`, {
    hint: `--until takes one of: ${CONDITION_FORMS}.`,
  });
}

function containerOf(text: string): { head: string; container: string } {
  const at = text.lastIndexOf(CONTAINER_SUFFIX);
  if (at < 0) {
    throw badCondition(`'${text}' names no container (…${CONTAINER_SUFFIX}NAME)`);
  }
  const container = text.slice(at + CONTAINER_SUFFIX.length);
  assertPositional('container', container);
  return { head: text.slice(0, at), container };
}

export function parseCondition(raw: string): Condition {
  if (raw.startsWith('healthy@')) {
    const { head, container } = containerOf(raw);
    if (head !== 'healthy') {
      throw badCondition(`'${raw}' is not healthy@container=NAME`);
    }
    return { kind: 'healthy', container };
  }
  if (raw.startsWith('log-contains:')) {
    const { head, container } = containerOf(raw);
    const pattern = head.slice('log-contains:'.length);
    if (pattern.length === 0 || pattern.length > MAX_WAIT_PATTERN_CHARS) {
      throw badCondition(`the log-contains regex must be 1-${MAX_WAIT_PATTERN_CHARS} characters`);
    }
    if (/[\0\r\n]/.test(pattern)) {
      throw badCondition('the log-contains regex must be on one line');
    }
    return { kind: 'log-contains', pattern, container };
  }
  if (raw.startsWith('port-open:')) {
    const text = raw.slice('port-open:'.length);
    const port = /^\d{1,5}$/.test(text) ? Number(text) : Number.NaN;
    if (!Number.isInteger(port) || port < 1 || port > 65_535) {
      throw badCondition(`port-open needs a port from 1 to 65535 (got '${text}')`);
    }
    return { kind: 'port-open', port };
  }
  if (raw.startsWith('url:')) {
    const rest = raw.slice('url:'.length);
    const at = rest.lastIndexOf(STATUS_SUFFIX);
    const status = at < 0 ? '200' : rest.slice(at + STATUS_SUFFIX.length);
    if (!/^[1-5]\d\d$/.test(status)) {
      throw badCondition(`url status must be a 3-digit HTTP status (got '${status}')`);
    }
    return { kind: 'url', url: localUrl(at < 0 ? rest : rest.slice(0, at), 'wait for'), status };
  }
  throw badCondition(`unknown condition '${raw}'`);
}

/** `--timeout` as the whole call's budget, bounded here as well as by the CLI. */
function budgetSec(ctx: OpContext): number {
  const raw = optStrOrNull(ctx, 'timeout');
  if (raw === null) {
    return WAIT_DEFAULT_TIMEOUT_SEC;
  }
  const value = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isInteger(value) || value < WAIT_MIN_TIMEOUT_SEC || value > WAIT_MAX_TIMEOUT_SEC) {
    throw new OpError(
      'INVALID_ARGS',
      `wait for: --timeout must be a whole number of seconds from ${WAIT_MIN_TIMEOUT_SEC} to ${WAIT_MAX_TIMEOUT_SEC}`,
    );
  }
  return value;
}

/** docker's own `--since` forms: a duration (`90s`, `5m`, `2h`), a unix time, or an RFC 3339 instant. */
const SINCE_PATTERN =
  /^(?:\d+(?:s|m|h)|\d{9,10}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})?)$/;

function sinceOf(ctx: OpContext, condition: Condition): string | null {
  const since = optStrOrNull(ctx, 'since');
  if (since === null) {
    return null;
  }
  if (condition.kind !== 'log-contains') {
    throw new OpError('INVALID_ARGS', 'wait for: --since applies to log-contains only');
  }
  if (!SINCE_PATTERN.test(since)) {
    throw new OpError(
      'INVALID_ARGS',
      `wait for: --since '${since}' is not a duration (5m), unix time or RFC 3339 instant`,
    );
  }
  return since;
}

const NO_HEALTHCHECK_EXIT = 4;
const NOT_MET_EXIT = 3;
const WAIT_LINE = /^__WAIT__ (ok|timeout|nohealthcheck) (\d+) (\d+) (\S*)$/m;

/** One shell function per condition: `check` sets `$st` to what it saw and returns 0 once met. */
function checkFunction(condition: Condition): string[] {
  switch (condition.kind) {
    case 'healthy':
      return [
        `c=${shq(condition.container)}`,
        'command -v docker >/dev/null 2>&1 || exit 127',
        'check() {',
        `  st=$(docker inspect --type container --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' -- "$c" 2>/dev/null) || st=missing`,
        `  if [ "$st" = none ]; then printf '__WAIT__ nohealthcheck %s %s none\\n' "$n" "$(($(now_ms) - start))"; exit ${NO_HEALTHCHECK_EXIT}; fi`,
        '  [ "$st" = healthy ]',
        '}',
      ];
    case 'log-contains':
      return [
        `c=${shq(condition.container)}`,
        `re=${shq(condition.pattern)}`,
        'command -v docker >/dev/null 2>&1 || exit 127',
        'check() {',
        '  now=$(date +%s)',
        '  if ! docker inspect --type container -- "$c" >/dev/null 2>&1; then st=missing; return 1; fi',
        '  if docker logs --since "$s" "$c" 2>&1 | grep -E -q -e "$re"; then st=matched; return 0; fi',
        '  st=no-match; s=$((now - 1)); return 1',
        '}',
      ];
    case 'port-open':
      return [
        `p=:${condition.port}`,
        'check() {',
        `  if command -v ss >/dev/null 2>&1; then l=$(ss -ltn 2>/dev/null); else l=$(netstat -ltn 2>/dev/null); fi`,
        `  if printf '%s\\n' "$l" | awk -v p="$p" 'NR > 1 { a = $4; if (length(a) > length(p) && substr(a, length(a) - length(p) + 1) == p) f = 1 } END { exit !f }'; then st=open; return 0; fi`,
        '  st=closed; return 1',
        '}',
      ];
    case 'url':
      return [
        `u=${shq(condition.url)}`,
        'command -v curl >/dev/null 2>&1 || exit 127',
        'check() {',
        `  st=$(${httpStatusCommand('"$u"', ` --max-time ${WAIT_URL_PROBE_TIMEOUT_SEC} --noproxy '*' --proto '=http,https'`)}) || true`,
        `  [ "$st" = ${condition.status} ]`,
        '}',
      ];
    default: {
      const exhaustive: never = condition;
      throw new Error(`unhandled wait condition: ${JSON.stringify(exhaustive)}`);
    }
  }
}

/** One ssh session polls until the condition holds or the deadline (the budget less its reply
 *  grace) passes; milliseconds come from /proc/uptime, which busybox `date` cannot give. */
function waitScript(ctx: OpContext): string {
  const condition = parseCondition(reqStr(ctx, 'until'));
  const since = sinceOf(ctx, condition);
  const deadlineMs = (budgetSec(ctx) - WAIT_REPLY_GRACE_SEC) * 1000;
  const lines = [
    `now_ms() { if [ -r /proc/uptime ]; then awk '{ printf "%d", $1 * 1000 }' /proc/uptime; else echo $(($(date +%s) * 1000)); fi; }`,
    `s=${since === null ? '$(date +%s)' : shq(since)}`,
    ...checkFunction(condition),
    'start=$(now_ms); n=0; st=',
    'while :; do',
    '  n=$((n + 1))',
    `  if check; then printf '__WAIT__ ok %s %s %s\\n' "$n" "$(($(now_ms) - start))" "$st"; exit 0; fi`,
    '  el=$(($(now_ms) - start))',
    `  if [ "$el" -ge ${deadlineMs} ]; then printf '__WAIT__ timeout %s %s %s\\n' "$n" "$el" "$st"; exit ${NOT_MET_EXIT}; fi`,
    `  sleep ${WAIT_POLL_INTERVAL_SEC}`,
    'done',
  ];
  return shellJoin(['sh', '-c', lines.join('\n')]);
}

export interface WaitResult {
  until: string;
  met: boolean;
  attempts: number;
  elapsed_ms: number;
  last_state: string;
}

function readWaitLine(stdout: string, ctx: OpContext): WaitResult | undefined {
  const [, outcome, attempts, elapsed, state] = WAIT_LINE.exec(stdout) ?? [];
  if (outcome === undefined) {
    return undefined;
  }
  return {
    until: reqStr(ctx, 'until'),
    met: outcome === 'ok',
    attempts: Number(attempts),
    elapsed_ms: Number(elapsed),
    last_state: state ?? '',
  };
}

function refineWaitError(_stderr: string, error: ErrorInfo, ctx: OpContext): ErrorInfo | undefined {
  if (error.remote_exit === NOT_MET_EXIT) {
    const budget = budgetSec(ctx);
    return {
      ...describeError(
        'COMMAND_TIMEOUT',
        `'${reqStr(ctx, 'until')}' was not met within ${budget - WAIT_REPLY_GRACE_SEC} s`,
        {
          hint: 'data.last_state says what the last check saw; give it longer with --timeout <sec>, or look at why with logs docker.',
        },
      ),
      remote_exit: error.remote_exit,
      phase: 'command',
      timeout_sec: budget,
    };
  }
  if (error.remote_exit === NO_HEALTHCHECK_EXIT) {
    return {
      ...describeError(
        'VALIDATION_ERROR',
        'that container defines no HEALTHCHECK, so it never becomes healthy',
        {
          hint: 'Wait on a log line (log-contains:<regex>@container=NAME) or a URL (url:<localhost-url>) instead.',
        },
      ),
      remote_exit: error.remote_exit,
    };
  }
  if (error.remote_exit === 127) {
    return {
      ...describeError(
        'COMMAND_FAILED',
        'the tool this condition needs (docker or curl) is not installed on the host',
      ),
      remote_exit: error.remote_exit,
    };
  }
  return undefined;
}

const waitFor: OpSpec<WaitResult> = {
  group: 'wait',
  name: 'for',
  summary:
    'Block until a condition holds on the host, polling in one ssh session: a container healthy, a log line, a listening port or a localhost URL status. Returns attempts and elapsed_ms.',
  args: [
    arg('until', 'flag', true, `The condition: ${CONDITION_FORMS}.`),
    arg(
      'timeout',
      'flag',
      false,
      `Seconds for the whole call (${WAIT_MIN_TIMEOUT_SEC}-${WAIT_MAX_TIMEOUT_SEC}, default ${WAIT_DEFAULT_TIMEOUT_SEC}); polling stops ${WAIT_REPLY_GRACE_SEC} s before it to report.`,
    ),
    arg(
      'since',
      'flag',
      false,
      'log-contains only: also match lines written since then (5m, a unix time, an RFC 3339 instant); default only lines written after the wait starts.',
    ),
  ],
  mutating: false,
  exposes: 'metadata',
  timeoutSec: WAIT_DEFAULT_TIMEOUT_SEC,
  output: 'raw',
  refineError: refineWaitError,
  shapeError: (raw: RawResult, ctx) => {
    const result = readWaitLine(raw.stdout, ctx);
    return result === undefined ? undefined : { ...result };
  },
  buildRemote: (ctx) => waitScript(ctx),
  shape: (parsed, ctx) => {
    const result = readWaitLine(parsed as string, ctx);
    if (result === undefined || !result.met) {
      throw new OpError('PARSE_ERROR', "wait for: the host's reply had no result line");
    }
    return result;
  },
};

export const waitOps = [waitFor] as OpSpec[];
