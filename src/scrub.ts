/**
 * The one owner of secret masking. `executeOp` runs `scrub` once over every envelope it builds
 * (an op's shaped data when the op `exposes` anything, plus every error); `files`/`config` ops
 * also mask whole env-shaped files with `maskEnvContent` before that.
 *
 * Masking is by shape and by key name, never by value: exact-value redaction ("mask any env
 * value of 6+ chars") was rejected — short secrets slip under the length floor and common words
 * that happen to be values mask ordinary prose.
 */

export const MASK = '***';
export const ENV_MASK = '***MASKED***';

/** Hardcoded, non-overridable — checked before the per-alias reveal-allowlist, so a key
 *  matching one of these patterns can never be revealed even if it was mistakenly added to
 *  reveal-allowlist.toml. Case-insensitive substring/suffix match against the key name only. */
export const REVEAL_DENYLIST_PATTERNS: RegExp[] = [
  /PASSWORD/i,
  /PASSWD/i,
  /SECRET/i,
  /TOKEN/i,
  /PRIVATE[_-]?KEY/i,
  /CREDENTIAL/i,
  /API[_-]?KEY/i,
  /_KEY$/i,
  /_PASS$/i,
];

const SECRET_NAME_FRAGMENTS = ['SECRET', 'TOKEN', 'PASSWORD', 'PASSWD', 'PASSPHRASE', 'CREDENTIAL'];
const SECRET_NAME_ENDINGS = ['PASS', 'DSN'];
const SECRET_NAME_SEGMENTS = new Set(SECRET_NAME_ENDINGS);
/** A last name segment joined without a separator (`privkey`, `TS_AUTHKEY`, `LICENSEKEY`): it is
 *  secret when the word right before `KEY` is a secret-ish one, so `monkey`, `turkey`, `hockey`,
 *  `whiskey` and `key` stay visible. `PASS` covers tracker `passkey`s, which are credentials. */
const JOINED_SECRET_KEY =
  /(?:PRIV|PRIVATE|MASTER|SIGNING|STRIPE|APP|LICENSE|API|SECRET|ENCRYPTION|ACCESS|AUTH|JWT|HMAC|SESSION|CRYPT|PRESHARED|CLIENT|DEPLOY|SSH|WEBHOOK|PASS)KEY$/;

/** A key name whose value is a secret: the reveal denylist, a name containing a secret word,
 *  a name ending in (or having a `_`/`.`/`-` segment equal to) PASS/DSN, a `_PWD`/`_PW` name, a
 *  camelCase `...Key`/`...Salt`, a last segment ending in a joined `<prefix>key` or equal to SALT,
 *  or a KEY segment in a name of two or more segments. A bare `key`, `url`, `APP_URL` or `monkey`
 *  is not: a URL's credentials are masked by its shape, not its name.
 *  `PORT`, `NODE_ENV` and `DB_HOST` are not — a host is not a secret by default. */
export function isSecretKey(name: string): boolean {
  if (REVEAL_DENYLIST_PATTERNS.some((pattern) => pattern.test(name))) {
    return true;
  }
  const upper = name.toUpperCase();
  if (SECRET_NAME_FRAGMENTS.some((fragment) => upper.includes(fragment))) {
    return true;
  }
  if (/[_.-]PWD?$/i.test(name) || /[a-z0-9](?:Key|Salt)$/.test(name)) {
    return true;
  }
  if (SECRET_NAME_ENDINGS.some((ending) => upper.endsWith(ending))) {
    return true;
  }
  const segments = upper.split(/[_.-]/);
  const last = segments[segments.length - 1] ?? '';
  return (
    JOINED_SECRET_KEY.test(last) ||
    last === 'SALT' ||
    segments.some((segment) => SECRET_NAME_SEGMENTS.has(segment)) ||
    (segments.length > 1 && segments.includes('KEY'))
  );
}

const ENV_FILE_SUFFIXES = ['.env', '.vars', '.secrets'];

/** Every secret-shaped file: a basename containing `.env` (`.env`, `.env.local`, `prod.env`) or
 *  ending `.vars`/`.secrets`, a `credentials*` file, a `*.pem`, or an ssh key named `id_*`. */
export function isEnvFile(path: string): boolean {
  const base = (path.split('/').pop() ?? path).toLowerCase();
  return (
    base.includes('.env') ||
    ENV_FILE_SUFFIXES.some((suffix) => base.endsWith(suffix)) ||
    base.startsWith('credentials') ||
    base.endsWith('.pem') ||
    base.startsWith('id_')
  );
}

/** How far a quoted value may run looking for its closing quote: an unclosed quote would
 *  otherwise rescan to the end of the text from every such line. 16 KiB holds a PEM key kept
 *  in one env var (a 4096-bit RSA key is ~3.3 KB); a longer quoted value is masked to end of line. */
const MAX_QUOTED_VALUE_CHARS = 16_384;

/** A value after `=`/`:` at line start: a double-quoted string (may span lines, honours `\"`),
 *  a single-quoted string (may span lines), or the rest of the line plus any `\`-continued lines. */
const LINE_VALUE = String.raw`"(?:[^"\\]|\\[\s\S]){0,${MAX_QUOTED_VALUE_CHARS}}"|'[^']{0,${MAX_QUOTED_VALUE_CHARS}}'|(?:[^\n]*\\\n)*[^\n]*`;
const KEY_NAME = String.raw`[A-Za-z_][\w.-]*`;
/** The unanchored rules start a name only where a run of name characters starts: starting after
 *  every `-` inside a run rescans the rest of it each time (quadratic: a 204 KB hyphenated line
 *  took 114 s). Nothing is lost — `isSecretKey` of a whole run is true whenever it is for any of
 *  its `-`-suffixes, since it matches substrings, endings and segments. */
const RUN_START = String.raw`(?<![\w.$-])`;
const RUN_KEY_NAME = String.raw`\w[\w.-]*`;

/** `[export ]KEY=value` at line start — the env-file shape `maskEnvContent` masks wholesale. */
const ENV_ASSIGNMENT = new RegExp(
  String.raw`^([ \t]*(?:export[ \t]+)?)(${KEY_NAME})([ \t]*=[ \t]*)(${LINE_VALUE})`,
  'gm',
);

/** `KEY=value`, `export KEY=value`, `key: value`, `"key": "value"`, `- key: value`, PHP
 *  `$key = 'value';` at line start. */
const KEYED_LINE = new RegExp(
  String.raw`^([ \t]*(?:-[ \t]+)?(?:export[ \t]+)?\$?)(["']?)(${KEY_NAME})\2([ \t]*[=:][ \t]*)(${LINE_VALUE})`,
  'gm',
);

const INLINE_QUOTED_VALUE = String.raw`"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'`;

/** A quoted secret name as a subscript being assigned: `$cfg[$i]['password'] = 'v'`, `conf["token"] = v`. */
const KEYED_SUBSCRIPT = new RegExp(
  String.raw`(\[[ \t]*)(["'])(${KEY_NAME})\2([ \t]*\][ \t]*=[ \t]*)(${INLINE_QUOTED_VALUE}|[^\s;,)\]]+)`,
  'g',
);

/** A call whose first argument is a quoted secret name and whose second is a quoted literal:
 *  `define('DB_PASSWORD', 'v')` (wp-config.php), `env('API_TOKEN', 'v')`. */
const KEYED_CALL_ARG = new RegExp(
  String.raw`(\b\w+[ \t]*\([ \t]*)(["'])(${KEY_NAME})\2([ \t]*,[ \t]*)(${INLINE_QUOTED_VALUE})`,
  'g',
);

/** The same pair anywhere in a line (`... password=x&user=y`, `{"token":"x"}`, `--secret=x`), and a
 *  hash-rocket pair (`'password' => 'x'`, `:password=>'x'`) whose value is a quoted or numeric
 *  literal — an arrow function `token => token.trim()` is code, not a secret. */
const KEYED_INLINE = new RegExp(
  String.raw`${RUN_START}(["']?)(-*${RUN_KEY_NAME})\1([ \t]*(?:=>[ \t]*(?=["'\d])|[=:][ \t]*))("(?:[^"\\\n]|\\.)*"|'[^'\n]*'|[^\s"',;&<>)}\]]+)`,
  'g',
);

/** A long base64/hex run right after a secret-ish word with only whitespace between (`--token <v>`). */
const KEYED_ADJACENT = new RegExp(
  String.raw`${RUN_START}(-*)(${RUN_KEY_NAME})([ \t]+)([A-Za-z0-9+/_-]{32,}={0,2})(?![\w+/=-])`,
  'g',
);

/** A dashed secret-named flag and its value after whitespace, any length (`--password <v>`). */
const FLAG_SPACED = new RegExp(
  String.raw`${RUN_START}(-+)(${RUN_KEY_NAME})([ \t]+)("[^"\n]*"|'[^'\n]*'|[^\s"'-][^\s"']*)`,
  'g',
);

interface ShapeRule {
  pattern: RegExp;
  replace: (match: string, ...groups: string[]) => string;
}

const PEM_LABEL = '[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?';
const HAS_CONTENT = /[^\s*]/;
const PEM_MARKER = new RegExp(`-----(BEGIN|END) (${PEM_LABEL})-----`, 'g');
const PEM_BEGIN_MARKER = new RegExp(`-----BEGIN ${PEM_LABEL}-----`, 'g');

/** How far a URL's password may run looking for the last `@` before the host: a bound keeps the
 *  rule linear on a long run with many `scheme://user:` starts and no `@`. 512 chars is far past
 *  any real password in a connection string. The password never runs across another `://` (a URL
 *  in the query string) and never starts with a port (`localhost:3000/api?email=a@b` has no userinfo). */
const MAX_URL_PASSWORD_CHARS = 512;

/** A query parameter carrying a URL signature (Azure SAS `sig`, S3 `X-Amz-Signature`, CloudFront
 *  `Signature`) — secret in a query string, while a `signature` key elsewhere is usually not. */
const SIGNATURE_PARAM = /^sig$|signature$/i;

/** Private-key PEM blocks, in one pass over the markers instead of a regex rescanning to the end
 *  of the text from every BEGIN (quadratic: 375 KB of BEGIN lines took 4 s). A BEGIN with a later
 *  END of the same label keeps both lines around a mask; then a BEGIN with no `-----END` after it
 *  keeps its line and masks the rest of the text. */
function maskPemBlocks(text: string): ScrubResult<string> {
  let count = 0;
  const markers = [...text.matchAll(PEM_MARKER)];
  const nextEnd: (number | undefined)[] = new Array(markers.length);
  const nearestEndByLabel = new Map<string, number>();
  for (let i = markers.length - 1; i >= 0; i -= 1) {
    const [, kind, label = ''] = markers[i] as RegExpMatchArray;
    if (kind === 'BEGIN') {
      nextEnd[i] = nearestEndByLabel.get(label);
    } else {
      nearestEndByLabel.set(label, i);
    }
  }
  let paired = '';
  let pos = 0;
  for (let i = 0; i < markers.length; i += 1) {
    const begin = markers[i] as RegExpMatchArray;
    const endIndex = nextEnd[i];
    const start = begin.index ?? 0;
    if (start < pos || endIndex === undefined) {
      continue;
    }
    const end = markers[endIndex] as RegExpMatchArray;
    const stop = (end.index ?? 0) + end[0].length;
    const replaced = `${begin[0]}\n${MASK}\n${end[0]}`;
    if (replaced !== text.slice(start, stop)) {
      count += 1;
    }
    paired += `${text.slice(pos, start)}${replaced}`;
    pos = stop;
  }
  let out = `${paired}${text.slice(pos)}`;

  const lastEnd = out.lastIndexOf('-----END');
  for (const begin of out.matchAll(PEM_BEGIN_MARKER)) {
    const bodyStart = (begin.index ?? 0) + begin[0].length;
    if (lastEnd >= bodyStart) {
      continue;
    }
    if (HAS_CONTENT.test(out.slice(bodyStart))) {
      out = `${out.slice(0, bodyStart)}\n${MASK}`;
      count += 1;
    }
    break;
  }
  return { value: out, count };
}

/** Value shapes that are secrets wherever they appear, independent of any key name. */
const SHAPE_RULES: ShapeRule[] = [
  {
    pattern: new RegExp(String.raw`^((?:(?!-----BEGIN)[\s\S])*?)(-----END ${PEM_LABEL}-----)`, 'g'),
    replace: (m, body = '', end = '') => (HAS_CONTENT.test(body) ? `${MASK}\n${end}` : m),
  },
  {
    pattern: /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+/g,
    replace: () => MASK,
  },
  {
    pattern:
      /(?<![\w-])(?:sk-[A-Za-z0-9_-]{20,}|[sr]k_(?:live|test)_[A-Za-z0-9]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|whsec_[A-Za-z0-9+/=]{20,})/g,
    replace: () => MASK,
  },
  {
    pattern: /(https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/)[A-Za-z0-9/_-]+/g,
    replace: (_m, head = '') => `${head}${MASK}`,
  },
  {
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    replace: () => MASK,
  },
  {
    pattern:
      /(https:\/\/(?:(?:canary|ptb)\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/)[A-Za-z0-9_-]+/g,
    replace: (_m, head = '') => `${head}${MASK}`,
  },
  {
    pattern: new RegExp(
      String.raw`\b([a-z][a-z0-9+.-]{0,31}:\/\/[^\s:/@]*:)(?!\d{1,5}[/?#])((?:(?!:\/\/)[^\s"'<>]){1,${MAX_URL_PASSWORD_CHARS}})(@)`,
      'gi',
    ),
    replace: (_m, head = '', _password, at = '') => `${head}${MASK}${at}`,
  },
  {
    pattern: /([?&])([\w.-]+)(=)([^&#\s"'<>]+)/g,
    replace: (m, lead = '', key = '', eq = '', value = '') =>
      (isSecretKey(key) || SIGNATURE_PARAM.test(key)) && !isMasked(value)
        ? `${lead}${key}${eq}${MASK}`
        : m,
  },
  {
    pattern:
      /\b(Authorization["']?[ \t]*[:=][ \t]*["']?(?:Basic|Digest|Token)[ \t]+)([^\s"',;]+)/gi,
    replace: (_m, head = '') => `${head}${MASK}`,
  },
  {
    pattern:
      /\b(Bearer[ \t]+)(?=[A-Za-z0-9._~+/-]*[0-9]|[A-Za-z0-9._~+/-]{16})([A-Za-z0-9._~+/-]+=*)/g,
    replace: (_m, head = '') => `${head}${MASK}`,
  },
  {
    pattern: /\b(Set-Cookie[ \t]*:[ \t]*[^=;\s]+=)([^;\r\n]+)/gi,
    replace: (m, head = '', value = '') => (isMasked(value) ? m : `${head}${MASK}`),
  },
  {
    pattern: /(?<![\w-])(Cookie[ \t]*:[ \t]*)([^\r\n]+)/gi,
    replace: (_m, head = '', value = '') => `${head}${value.replace(/=[^;]*/g, `=${MASK}`)}`,
  },
  {
    pattern: /<([A-Za-z_][\w.-]{0,63})>([^<]+)<\/\1>/g,
    replace: (m, tag = '', value = '') =>
      isSecretKey(tag) && !isMasked(value) ? `<${tag}>${MASK}</${tag}>` : m,
  },
  {
    pattern:
      /(\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b[^\n]{0,256}?[ \t]-p)([^\s"']+)/g,
    replace: (m, head = '', value = '') => (isMasked(value) ? m : `${head}${MASK}`),
  },
];

export interface ScrubOptions {
  /** Keys a `--reveal` already cleared (denylist + reveal-allowlist): their lines are left as-is. */
  revealKeys?: ReadonlySet<string>;
  /** Per-alias extra patterns (reveal-allowlist.toml `[<alias>.scrub] extra_patterns`): every match is masked. */
  extraPatterns?: RegExp[];
  /** Exact strings masked wherever they stand as a whole word — the db connection fields an
   *  error echoes (`role "<user>" does not exist`), which an envelope never carries. */
  literals?: string[];
}

export interface ScrubResult<T> {
  value: T;
  count: number;
}

function isMasked(value: string): boolean {
  const bare = value.replace(/^["']|["']$/g, '');
  return bare === MASK || bare === ENV_MASK;
}

function literalPattern(literal: string): RegExp {
  const escaped = literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?<![\\w.-])${escaped}(?![\\w.-])`, 'g');
}

function maskedValue(value: string, mask: string): string {
  const quote = value.startsWith('"') || value.startsWith("'") ? value[0] : '';
  return `${quote}${mask}${quote}`;
}

const PLACEHOLDER = (index: number): string => `\uE000${index}\uE001`;

/** Lines assigning a revealed key are lifted out before the key-name rules run and put back
 *  after; the value-shape rules have already run over them, so a revealed URL keeps its password masked. */
function protectRevealedLines(text: string, revealKeys: ReadonlySet<string>): [string, string[]] {
  const kept: string[] = [];
  if (revealKeys.size === 0) {
    return [text, kept];
  }
  const protectedText = text.replace(KEYED_LINE, (match, _lead, _q, key: string) => {
    if (!revealKeys.has(key)) {
      return match;
    }
    kept.push(match);
    return PLACEHOLDER(kept.length - 1);
  });
  return [protectedText, kept];
}

/** Masks every secret in one string; `count` is how many values were replaced. */
export function scrubText(text: string, options: ScrubOptions = {}): ScrubResult<string> {
  const revealKeys = options.revealKeys ?? new Set<string>();
  let out = text;
  let count = 0;

  const literals = (options.literals ?? []).filter((literal) => literal.length > 0);
  for (const literal of [...literals].sort((a, b) => b.length - a.length)) {
    out = out.replace(literalPattern(literal), () => {
      count += 1;
      return MASK;
    });
  }
  for (const pattern of options.extraPatterns ?? []) {
    out = out.replace(pattern, () => {
      count += 1;
      return MASK;
    });
  }
  const pem = maskPemBlocks(out);
  out = pem.value;
  count += pem.count;
  for (const rule of SHAPE_RULES) {
    out = out.replace(rule.pattern, (...args: unknown[]) => {
      const groups = args.slice(0, -2).map((arg) => (typeof arg === 'string' ? arg : ''));
      const [match = '', ...rest] = groups;
      const replaced = rule.replace(match, ...rest);
      if (replaced !== match) {
        count += 1;
      }
      return replaced;
    });
  }
  const [protectedText, kept] = protectRevealedLines(out, revealKeys);
  out = protectedText;
  out = out.replace(
    KEYED_LINE,
    (match, lead: string, q: string, key: string, sep: string, value: string) => {
      if (!isSecretKey(key) || revealKeys.has(key) || value.length === 0 || isMasked(value)) {
        return match;
      }
      count += 1;
      return `${lead}${q}${key}${q}${sep}${maskedValue(value, MASK)}`;
    },
  );
  out = out.replace(KEYED_INLINE, (match, q: string, key: string, sep: string, value: string) => {
    if (!isSecretKey(key) || revealKeys.has(key) || isMasked(value)) {
      return match;
    }
    count += 1;
    return `${q}${key}${q}${sep}${maskedValue(value, MASK)}`;
  });
  for (const pattern of [KEYED_SUBSCRIPT, KEYED_CALL_ARG]) {
    out = out.replace(
      pattern,
      (match, lead: string, q: string, key: string, sep: string, value: string) => {
        if (!isSecretKey(key) || revealKeys.has(key) || isMasked(value)) {
          return match;
        }
        count += 1;
        return `${lead}${q}${key}${q}${sep}${maskedValue(value, MASK)}`;
      },
    );
  }
  out = out.replace(KEYED_ADJACENT, (match, dashes: string, key: string, gap: string) => {
    if (!isSecretKey(key) || revealKeys.has(key)) {
      return match;
    }
    count += 1;
    return `${dashes}${key}${gap}${MASK}`;
  });
  out = out.replace(
    FLAG_SPACED,
    (match, dashes: string, key: string, gap: string, value: string) => {
      if (!isSecretKey(key) || revealKeys.has(key) || isMasked(value)) {
        return match;
      }
      count += 1;
      return `${dashes}${key}${gap}${maskedValue(value, MASK)}`;
    },
  );

  if (kept.length > 0) {
    out = out.replace(/\uE000(\d+)\uE001/g, (_m, index: string) => kept[Number(index)] ?? '');
  }
  return { value: out, count };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Walks any shaped payload: every string goes through `scrubText`, and every string or number
 * under a secret key name (`{"password": 123}`, `{"tokens": ["x"]}`, `{"password_hash": {...}}`
 * from a `db query` row) is masked whole, at any depth. Returns a copy; the input is never mutated.
 */
export function scrub<T>(value: T, options: ScrubOptions = {}): ScrubResult<T> {
  let count = 0;
  const revealKeys = options.revealKeys ?? new Set<string>();
  const underSecret = (key: string): boolean => isSecretKey(key) && !revealKeys.has(key);
  const walk = (node: unknown, secret: boolean): unknown => {
    if (typeof node === 'string') {
      if (secret && node.length > 0 && node !== MASK) {
        count += 1;
        return MASK;
      }
      const result = scrubText(node, options);
      count += result.count;
      return result.value;
    }
    if (secret && (typeof node === 'number' || typeof node === 'bigint')) {
      count += 1;
      return MASK;
    }
    if (Array.isArray(node)) {
      return node.map((item) => walk(item, secret));
    }
    if (isPlainObject(node)) {
      const copy: Record<string, unknown> = {};
      for (const [childKey, child] of Object.entries(node)) {
        copy[childKey] = walk(child, secret || underSecret(childKey));
      }
      return copy;
    }
    return node;
  };
  const scrubbed = walk(value, false) as T;
  return { value: scrubbed, count };
}

const PEM_BEGIN_LINE = new RegExp(`-----BEGIN ${PEM_LABEL}-----`);
const PEM_END_LINE = new RegExp(`-----END ${PEM_LABEL}-----`);
/** Only quotes and separators (after escaped `\n`s and whitespace are dropped) — what sits around
 *  a marker that is the whole line (`-----END ...-----"`, a YAML `key: "-----BEGIN ...-----`). */
const PEM_MARKER_EDGE = /^["',;)}\]]*$/;
const PEM_BODY_CHUNK = /^[A-Za-z0-9+/=]{16}$/;

const bareSide = (text: string): string => text.replaceAll('\\n', ' ').trim();

/** A BEGIN opens a block only when nothing but edge characters follow it, or a base64 body does:
 *  `note: expected -----BEGIN RSA PRIVATE KEY----- header` is prose about a key. */
function opensPemBlock(line: string): boolean {
  const begin = PEM_BEGIN_LINE.exec(line);
  if (!begin) {
    return false;
  }
  const after = bareSide(line.slice(begin.index + begin[0].length));
  return PEM_MARKER_EDGE.test(after) || PEM_BODY_CHUNK.test(after.slice(0, 16));
}

/** An END closes a body whose BEGIN was cut off only when the marker is the whole line, or ends a
 *  base64 body on it: `must end with -----END RSA PRIVATE KEY-----` is prose about a key. */
function isLonePemEnd(line: string): boolean {
  const end = PEM_END_LINE.exec(line);
  if (!end) {
    return false;
  }
  const before = bareSide(line.slice(0, end.index));
  const after = bareSide(line.slice(end.index + end[0].length));
  return (
    PEM_MARKER_EDGE.test(after) &&
    (PEM_MARKER_EDGE.test(before) || PEM_BODY_CHUNK.test(before.slice(-16)))
  );
}

/** For output already split into lines (`files tail`, `logs *`), where no single string holds
 *  both ends of a PEM block: every line between a private-key BEGIN and its END is masked, and a
 *  lone END (its BEGIN cut off by `-n`) masks every line before it since the output start or the
 *  previous END. A line that only mentions a marker in prose does neither. */
export function maskPemLines(lines: readonly string[]): string[] {
  const out = [...lines];
  let inside = false;
  let bodyStart = 0;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    const isEnd = PEM_END_LINE.test(line);
    if (inside) {
      if (isEnd) {
        inside = false;
        bodyStart = i + 1;
      } else {
        out[i] = MASK;
      }
      continue;
    }
    if (opensPemBlock(line)) {
      inside = !isEnd;
      bodyStart = i + 1;
      continue;
    }
    if (isLonePemEnd(line)) {
      for (let j = bodyStart; j < i; j += 1) {
        out[j] = MASK;
      }
      bodyStart = i + 1;
    }
  }
  return out;
}

/** Whole-file masking for an env-shaped file: every `[export ]KEY=value` (quoted or continued
 *  across lines) becomes `KEY=***MASKED***` unless `--reveal` named the key. */
export function maskEnvContent(content: string, revealedKeys: ReadonlySet<string>): string {
  return content.replace(
    ENV_ASSIGNMENT,
    (match, lead: string, key: string, sep: string, value: string) => {
      if (revealedKeys.has(key)) {
        return match;
      }
      return `${lead}${key}${sep}${maskedValue(value, ENV_MASK)}`;
    },
  );
}
