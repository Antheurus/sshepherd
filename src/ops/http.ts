import { readFileSync } from 'node:fs';
import { describeError } from '../errors.ts';
import {
  HTTP_BODY_MAX_BYTES,
  HTTP_CONNECT_TIMEOUT_SEC,
  HTTP_OP_TIMEOUT_SEC,
  HTTP_REQUEST_BODY_MAX_BYTES,
  HTTP_REQUEST_TIMEOUT_SEC,
} from '../limits.ts';
import { arg, assertPositional, optStrOrNull, reqStr } from '../op-args.ts';
import { shellJoin, shq } from '../quote.ts';
import { didYouMean } from '../suggest.ts';
import { declaredContainers } from '../targets.ts';
import { type ErrorInfo, type OpContext, OpError, type OpSpec, Premasked } from '../types.ts';
import { assertPathAllowed } from './config.ts';

// The `--auth` credential is read into a shell variable on the host and reaches curl and awk only
// through stdin and the environment: never an argv, never the wire.

const LOOPBACK_V4 = /^127(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

/** The URL as curl will receive it: re-serialised by the WHATWG parser, so curl and this check
 *  read the same host. Only the host's own loopback is reachable — anything else is `INVALID_ARGS`. */
export function localUrl(raw: string, what: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new OpError('INVALID_ARGS', `${what}: '${raw}' is not a URL`, {
      hint: 'Pass a full URL such as http://127.0.0.1:8080/health.',
    });
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new OpError('INVALID_ARGS', `${what}: only http and https URLs are allowed`, {
      hint: 'Pass an http:// or https:// URL on the host itself.',
    });
  }
  if (url.username !== '' || url.password !== '') {
    throw new OpError('INVALID_ARGS', `${what}: the URL carries credentials`, {
      hint: 'Drop the user:password part; name where the host keeps the credential (env:KEY@container=NAME or env:KEY@file=PATH) in the auth flag.',
    });
  }
  const host = url.hostname;
  if (host !== 'localhost' && host !== '[::1]' && !LOOPBACK_V4.test(host)) {
    throw new OpError(
      'INVALID_ARGS',
      `${what}: '${host}' is not localhost — only 127.0.0.1, ::1 and localhost on the host are reachable`,
      {
        hint: "Probe the service from the host it runs on: use that host's alias with a 127.0.0.1 URL.",
      },
    );
  }
  return url.href;
}

interface AuthSource {
  key: string;
  kind: 'container' | 'file';
  source: string;
}

const AUTH_PATTERN = /^env:([A-Za-z_][A-Za-z0-9_]*)@(container|file)=(.+)$/;
const HEADER_NAME = /^[A-Za-z0-9-]{1,64}$/;

function authSource(ctx: OpContext, command: string): AuthSource | null {
  const raw = optStrOrNull(ctx, 'auth');
  if (raw === null) {
    if (optStrOrNull(ctx, 'auth-header') !== null) {
      throw new OpError(
        'INVALID_ARGS',
        `${command}: --auth-header is only read together with the auth flag`,
        {
          hint: 'Name where the credential lives (env:KEY@container=NAME or env:KEY@file=PATH) in the auth flag.',
        },
      );
    }
    return null;
  }
  const [, key, kind, source] = AUTH_PATTERN.exec(raw) ?? [];
  if (key === undefined || (kind !== 'container' && kind !== 'file') || source === undefined) {
    throw new OpError(
      'INVALID_ARGS',
      `${command}: the auth flag takes env:KEY@container=NAME or env:KEY@file=PATH`,
      {
        hint: 'KEY is the variable name only (letters, digits, _); the value is read on the host.',
      },
    );
  }
  if (kind === 'container') {
    assertPositional('container', source);
    const declared = declaredContainers(ctx.alias);
    if (!declared.includes(source)) {
      throw new OpError(
        'VALIDATION_ERROR',
        `${command}: the auth container '${source}' is not declared for alias '${ctx.alias}' in targets.toml`,
        {
          hint: 'A human lists it in containers = [...] on a targets.toml entry whose alias is this one; the agent never widens its own list.',
          did_you_mean: didYouMean(source, declared),
        },
      );
    }
  } else {
    assertPositional('path', source);
    assertPathAllowed('files', ctx, source);
  }
  return { key, kind, source };
}

/** `Authorization: Bearer <value>` unless `--auth-header NAME` asks for `NAME: <value>`. */
function headerPrefix(ctx: OpContext, command: string): string {
  const name = optStrOrNull(ctx, 'auth-header');
  if (name === null) {
    return 'Authorization: Bearer ';
  }
  if (!HEADER_NAME.test(name)) {
    throw new OpError('INVALID_ARGS', `${command}: --auth-header '${name}' is not a header name`, {
      hint: 'Use letters, digits and - only, e.g. X-Api-Key.',
    });
  }
  return `${name}: `;
}

const SOURCE_MISSING = '__AUTH_SOURCE_MISSING__';
const KEY_MISSING = '__AUTH_KEY_MISSING__';
const HEAD_MARK = '__HTTP__';
const BODY_MARK = '__BODY__';
const VALUE_ENV = 'SSHEPHERD_AUTH_VALUE';

/** The value of `k` in `docker inspect`'s Env, one `KEY=value` per line. */
const CONTAINER_VALUE_AWK = 'index($0, k "=") == 1 { print substr($0, length(k) + 2); exit }';

/** The value of `k` in a dotenv file, read the way dotenv loaders read one line: `[export ]KEY =
 *  value`, a quoted value up to its closing quote, an unquoted one without a trailing `# comment`;
 *  the last assignment wins. */
const DOTENV_VALUE_AWK = String.raw`
{
  line = $0
  sub(/\r$/, "", line); sub(/^[ \t]+/, "", line); sub(/^export[ \t]+/, "", line)
  if (index(line, k) != 1) next
  rest = substr(line, length(k) + 1)
  if (rest !~ /^[ \t]*=/) next
  sub(/^[ \t]*=[ \t]*/, "", rest)
  q = substr(rest, 1, 1)
  if (q == "\"" || q == "'") {
    rest = substr(rest, 2); p = index(rest, q); if (p > 0) rest = substr(rest, 1, p - 1)
  } else {
    sub(/[ \t]+#.*$/, "", rest); sub(/[ \t]+$/, "", rest)
  }
  v = rest
}
END { if (v != "") print v }
`;

/** One curl config line built from the environment, escaped for curl's quoted-string syntax. */
const CURL_HEADER_AWK = String.raw`BEGIN { v = ENVIRON["${VALUE_ENV}"]; gsub(/[\\"]/, "\\\\&", v); printf "header = \"%s%s\"\n", p, v }`;

/** Every occurrence of the credential in the body becomes `***`; the count goes to the file `cf`. */
const MASK_VALUE_AWK = `
BEGIN { v = ENVIRON["${VALUE_ENV}"]; n = 0 }
{
  line = $0; out = ""
  if (v != "") { while ((i = index(line, v)) > 0) { out = out substr(line, 1, i - 1) "***"; line = substr(line, i + length(v)); n++ } }
  print out line
}
END { print n > cf }
`;

/** Names of the last header block curl dumped (a `100 Continue` block comes first); values stay. */
const HEADER_NAMES_AWK = String.raw`
/^HTTP\// { n = 0; next }
{ sub(/\r$/, ""); i = index($0, ":"); if (i > 1) { n++; h[n] = substr($0, 1, i - 1) } }
END { for (j = 1; j <= n; j++) print h[j] }
`;

function resolveLines(auth: AuthSource): string[] {
  const lines = [`k=${shq(auth.key)}`];
  if (auth.kind === 'container') {
    lines.push(
      `c=${shq(auth.source)}`,
      'command -v docker >/dev/null 2>&1 || exit 127',
      `e=$(docker inspect --type container --format '{{range .Config.Env}}{{println .}}{{end}}' -- "$c" 2>/dev/null) || { echo ${SOURCE_MISSING}; exit 0; }`,
      `v=$(printf '%s\\n' "$e" | awk -v k="$k" ${shq(CONTAINER_VALUE_AWK)})`,
    );
  } else {
    lines.push(
      `f=${shq(auth.source)}`,
      `[ -f "$f" ] || { echo ${SOURCE_MISSING}; exit 0; }`,
      `v=$(awk -v k="$k" ${shq(DOTENV_VALUE_AWK)} "$f")`,
    );
  }
  lines.push(`[ -n "$v" ] || { echo ${KEY_MISSING}; exit 0; }`);
  return lines;
}

/** `--json @file` reads a local file, `--json '<text>'` takes the text; either must parse as JSON. */
function jsonBody(ctx: OpContext): string | null {
  const raw = optStrOrNull(ctx, 'json');
  if (raw === null) {
    return null;
  }
  let text = raw;
  if (raw.startsWith('@')) {
    try {
      text = readFileSync(raw.slice(1), 'utf8');
    } catch {
      throw new OpError(
        'INVALID_ARGS',
        `http send: local file '${raw.slice(1)}' not found or unreadable`,
        { hint: '--json @PATH names a LOCAL file; --json TEXT sends the text itself.' },
      );
    }
  }
  if (Buffer.byteLength(text, 'utf8') > HTTP_REQUEST_BODY_MAX_BYTES) {
    throw new OpError(
      'INVALID_ARGS',
      `http send: the --json body is over ${HTTP_REQUEST_BODY_MAX_BYTES} bytes`,
    );
  }
  try {
    JSON.parse(text);
  } catch {
    throw new OpError('INVALID_ARGS', 'http send: the --json body is not valid JSON');
  }
  return text;
}

/** The whole request as one remote script: resolve the credential (if any) into `$v`, run curl with
 *  the header on stdin, then print the status line, the header names and the capped, masked body. */
export function httpScript(ctx: OpContext, method: string): string {
  const command = `http ${method === 'GET' ? 'get' : 'send'}`;
  const url = localUrl(reqStr(ctx, 'url'), command);
  const auth = authSource(ctx, command);
  const prefix = auth === null ? '' : headerPrefix(ctx, command);
  const body = method === 'GET' ? null : jsonBody(ctx);
  const curl = [
    'curl -sS -o "$t/body" -D "$t/head"',
    `-w ${shq('%{http_code} %{time_total} %{size_download}')}`,
    `--max-time ${HTTP_REQUEST_TIMEOUT_SEC} --connect-timeout ${HTTP_CONNECT_TIMEOUT_SEC}`,
    `--noproxy ${shq('*')} --proto ${shq('=http,https')} -X ${shq(method)}`,
    ...(body === null
      ? []
      : [`-H ${shq('Content-Type: application/json')} --data-binary @"$t/req"`]),
    ...(auth === null ? [] : ['-K -']),
    '"$u"',
  ].join(' ');
  const request =
    auth === null
      ? curl
      : `${VALUE_ENV}="$v" awk -v p=${shq(prefix)} ${shq(CURL_HEADER_AWK)} | ${curl}`;
  const lines = [
    'command -v curl >/dev/null 2>&1 || exit 127',
    't=$(mktemp -d) || exit 70',
    `trap 'rm -rf "$t"' EXIT`,
    `u=${shq(url)}`,
    'v=',
    ...(auth === null ? [] : resolveLines(auth)),
    ...(body === null
      ? []
      : [
          `printf '%s' ${shq(Buffer.from(body, 'utf8').toString('base64'))} | base64 -d > "$t/req" || exit 70`,
        ]),
    `w=$(${request}) || exit $?`,
    'set -- $w',
    `head -c ${HTTP_BODY_MAX_BYTES} "$t/body" > "$t/cap"`,
    `a=$(tr -d '\\000' < "$t/cap" | wc -c); b=$(wc -c < "$t/cap")`,
    'bin=0; if [ $((a)) -ne $((b)) ]; then bin=1; fi',
    `nl=0; case "$(tail -c 1 "$t/cap" | od -An -tx1)" in *0a*) nl=1 ;; esac`,
    `if [ "$bin" = 0 ]; then ${VALUE_ENV}="$v" awk -v cf="$t/n" ${shq(MASK_VALUE_AWK)} "$t/cap" > "$t/out"; else : > "$t/out"; echo 0 > "$t/n"; fi`,
    `printf '${HEAD_MARK} %s %s %s %s %s %s\\n' "$1" "$2" "$3" "$(cat "$t/n")" "$nl" "$bin"`,
    `awk ${shq(HEADER_NAMES_AWK)} "$t/head"`,
    `echo ${BODY_MARK}`,
    'cat "$t/out"',
  ];
  return shellJoin(['sh', '-c', lines.join('\n')]);
}

export interface HttpResult {
  status: number;
  ms: number;
  headers_names: string[];
  /** Null when the body held a NUL byte (binary): only its size is reported. */
  body: string | null;
  body_bytes: number;
  body_truncated: boolean;
  body_binary: boolean;
}

const HEAD_LINE = /^__HTTP__ (\d{3}) (\d+(?:\.\d+)?) (\d+) (\d+) ([01]) ([01])$/;

export function shapeHttp(text: string, ctx: OpContext, command: string): Premasked<HttpResult> {
  const trimmed = text.trim();
  if (trimmed === SOURCE_MISSING || trimmed === KEY_MISSING) {
    const auth = optStrOrNull(ctx, 'auth') ?? '';
    throw new OpError(
      'VALIDATION_ERROR',
      trimmed === SOURCE_MISSING
        ? `${command}: the auth source in '${auth}' does not exist on the host`
        : `${command}: the auth key in '${auth}' is not set (or is empty) on the host`,
      {
        hint: 'Check the container with env keys --container NAME, or the file with env keys --path PATH.',
      },
    );
  }
  const headEnd = text.indexOf('\n');
  const head = HEAD_LINE.exec(headEnd < 0 ? text : text.slice(0, headEnd));
  const bodyAt = text.indexOf(`\n${BODY_MARK}\n`, Math.max(headEnd - 1, 0));
  if (head === null || bodyAt < 0) {
    throw new OpError('PARSE_ERROR', `${command}: the host's reply had no status line`);
  }
  const [, status, seconds, size, masked, endsWithNewline, binary] = head;
  const names = text
    .slice(headEnd + 1, bodyAt)
    .split('\n')
    .filter((name) => name.length > 0);
  let body = text.slice(bodyAt + BODY_MARK.length + 2);
  if (endsWithNewline === '0' && body.endsWith('\n')) {
    body = body.slice(0, -1);
  }
  const bytes = Number(size);
  return new Premasked(
    {
      status: Number(status),
      ms: Math.round(Number(seconds) * 1000),
      headers_names: names,
      body: binary === '1' ? null : body,
      body_bytes: bytes,
      body_truncated: bytes > HTTP_BODY_MAX_BYTES,
      body_binary: binary === '1',
    },
    Number(masked),
  );
}

/** curl's own exit codes read as what happened, not as a generic `COMMAND_FAILED`. */
function refineCurlError(_stderr: string, error: ErrorInfo, ctx: OpContext): ErrorInfo | undefined {
  const exit = error.remote_exit;
  if (exit === 28) {
    return {
      ...describeError(
        'COMMAND_TIMEOUT',
        `the request did not finish within ${HTTP_REQUEST_TIMEOUT_SEC} s`,
        {
          hint: 'The service on the host is hung or very slow; check it with logs docker or services healthcheck.',
        },
      ),
      remote_exit: exit,
      phase: 'command',
      timeout_sec: HTTP_REQUEST_TIMEOUT_SEC,
    };
  }
  if (exit === 7) {
    return {
      ...describeError(
        'COMMAND_FAILED',
        `nothing accepted the connection at ${String(ctx.args.url)}`,
        {
          hint: 'See which ports listen with check ports, and whether the service runs with services ps.',
          next: `sshepherd check ports ${ctx.alias}`,
        },
      ),
      remote_exit: exit,
    };
  }
  if (exit === 127) {
    return {
      ...describeError(
        'COMMAND_FAILED',
        'curl (or docker, for an auth container) is not installed on the host',
        { hint: 'Install curl on the host, or probe the service with services healthcheck.' },
      ),
      remote_exit: exit,
    };
  }
  return undefined;
}

const URL_ARG = arg(
  'url',
  'positional',
  true,
  'URL on the host itself — http(s)://127.0.0.1, ::1 or localhost only; redirects are not followed.',
);
const AUTH_ARGS = [
  arg(
    'auth',
    'flag',
    false,
    'env:KEY@container=NAME (a container in containers = [...] of targets.toml) or env:KEY@file=PATH (on files-allowlist.toml): read on the host and sent as a header; the value never leaves the host.',
  ),
  arg(
    'auth-header',
    'flag',
    false,
    'Header the --auth value goes in (e.g. X-Api-Key); default Authorization: Bearer <value>.',
  ),
];

const SEND_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

function sendMethod(ctx: OpContext): string {
  const method = reqStr(ctx, 'method').toUpperCase();
  if (!SEND_METHODS.includes(method)) {
    throw new OpError(
      'INVALID_ARGS',
      `http send: method must be one of ${SEND_METHODS.join(', ')}`,
      {
        hint: 'A GET needs no confirmation: use http get.',
        did_you_mean: didYouMean(method, SEND_METHODS),
      },
    );
  }
  return method;
}

const httpGet: OpSpec<HttpResult> = {
  group: 'http',
  name: 'get',
  summary:
    'GET a localhost URL from the host itself (curl runs there): status, ms, response header names (values stay on the host) and the body, capped and scrubbed.',
  args: [URL_ARG, ...AUTH_ARGS],
  mutating: false,
  exposes: 'content',
  timeoutSec: HTTP_OP_TIMEOUT_SEC,
  output: 'raw',
  refineError: refineCurlError,
  buildRemote: (ctx) => httpScript(ctx, 'GET'),
  shape: (parsed, ctx) => shapeHttp(parsed as string, ctx, 'http get'),
};

const httpSend: OpSpec<HttpResult> = {
  group: 'http',
  name: 'send',
  summary:
    'POST/PUT/PATCH/DELETE to a localhost URL from the host itself, optionally with a JSON body; same result as http get. Needs --yes.',
  args: [
    arg('method', 'positional', true, 'POST, PUT, PATCH or DELETE.'),
    URL_ARG,
    arg(
      'json',
      'flag',
      false,
      `Request body: @PATH reads a LOCAL file, otherwise the text itself; must be JSON, at most ${HTTP_REQUEST_BODY_MAX_BYTES} bytes.`,
    ),
    ...AUTH_ARGS,
  ],
  mutating: true,
  exposes: 'content',
  timeoutSec: HTTP_OP_TIMEOUT_SEC,
  output: 'raw',
  refineError: refineCurlError,
  hiddenArgs: ['json'],
  buildRemote: (ctx) => httpScript(ctx, sendMethod(ctx)),
  shape: (parsed, ctx) => shapeHttp(parsed as string, ctx, 'http send'),
};

export const httpOps = [httpGet, httpSend] as OpSpec[];
