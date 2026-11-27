/**
 * The one owner of secret masking. `executeOp` runs `scrub` once over every envelope it builds
 * (an op's shaped data when the op `exposes` anything, plus every error); `files`/`config` ops
 * also mask whole env-shaped files with `maskEnvContent` before that.
 *
 * Masking is by shape and by key name, never by value: exact-value redaction ("mask any env
 * value of 6+ chars") was rejected — short secrets slip under the length floor and common words
 * that happen to be values mask ordinary prose.
 */

import {
  ENV_BLOCK_MIN_LINES,
  MAX_HOSTNAME_CHARS,
  MAX_IDENTITY_GAP_CHARS,
  MAX_LABEL_HEX_TAIL_CHARS,
  MAX_NESTED_ASSIGNMENT_DEPTH,
  MAX_PEM_LONE_END_SCAN_LINES,
  MAX_PSQL_TYPE_NAME_CHARS,
  MIN_BARE_HOSTNAME_CHARS,
  MIN_MASKED_USER_CHARS,
} from './limits.ts';

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
const SECRET_NAME_ENDINGS = ['DSN'];
const SECRET_NAME_SEGMENTS = new Set(['PASS', 'DSN']);
/** A last name segment joined without a separator (`privkey`, `TS_AUTHKEY`, `LICENSEKEY`): it is
 *  secret when the word right before `KEY` is a secret-ish one, so `monkey`, `turkey`, `hockey`,
 *  `whiskey` and `key` stay visible. A joined `passkey` is `isJoinedPassKey`'s. */
const JOINED_SECRET_KEY =
  /(?:PRIV|PRIVATE|MASTER|SIGNING|STRIPE|APP|LICENSE|API|SECRET|ENCRYPTION|ACCESS|AUTH|JWT|HMAC|SESSION|CRYPT|PRESHARED|CLIENT|DEPLOY|SSH|WEBHOOK)KEY$/;

/** Values a flag holds: under a joined `pass` name they say the name is a switch, not a password. */
const BOOLEAN_WORDS = new Set([
  'true',
  'false',
  'yes',
  'no',
  'on',
  'off',
  'enabled',
  'disabled',
  '0',
  '1',
  'null',
  'none',
]);

function isBooleanWord(value: string): boolean {
  return BOOLEAN_WORDS.has(
    value
      .trim()
      .replace(/^["']|["']$/g, '')
      .toLowerCase(),
  );
}

/** A name whose last segment ends in a joined `pass` or `passkey` (`bypass`, `compass`, `firstPass`,
 *  `DBPASS`, a tracker `passkey`): a password only when its value is not a boolean word, so
 *  `bypass=true` stays visible while `dbpass=hunter2` does not. */
function isJoinedPassKey(name: string): boolean {
  const last = name.toUpperCase().split(/[_.-]/).pop() ?? '';
  return last.endsWith('PASS') || last.endsWith('PASSKEY');
}

/** `isSecretKey`, plus a joined-`pass` name whose value is not a boolean word. */
function isSecretPair(name: string, value: string): boolean {
  return isSecretKey(name) || (isJoinedPassKey(name) && !isBooleanWord(value));
}

/** A key name whose value is a secret whatever it holds: the reveal denylist, a name containing a
 *  secret word, a name ending in DSN or having a `_`/`.`/`-` segment equal to PASS/DSN, a
 *  `_PWD`/`_PW` name, a camelCase `...Key`/`...Salt`, a last segment ending in a joined
 *  `<prefix>key` or equal to SALT or AUTH (docker's `"auth": "<base64 user:password>"`), or a KEY segment in a name of two or more segments. A bare
 *  `key`, `url`, `APP_URL` or `monkey` is not: a URL's credentials are masked by its shape, not its
 *  name. `PORT`, `NODE_ENV` and `DB_HOST` are not — a host is not a secret by default. */
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
    last === 'AUTH' ||
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

/** `operator does not exist: integer = text` (or `- text` for a prefix operator): psql names the
 *  operand types, which are catalog names. A computed value echoed through `::regoper` comes back as
 *  one token with no blank, since a name with one is refused as `invalid name syntax` first. */
const PSQL_TYPE_NAME = String.raw`[A-Za-z_"][\w."]{0,${MAX_PSQL_TYPE_NAME_CHARS}}(?: [A-Za-z_][\w"]{0,${MAX_PSQL_TYPE_NAME_CHARS}}){0,3}(?:\[\])*`;
const OPERATOR_SIGNATURE = new RegExp(
  String.raw`^(?:${PSQL_TYPE_NAME} )?(?:[A-Za-z_]\w*\.)?[-+*/<>=~!@#%^&|\`?]{1,63} ${PSQL_TYPE_NAME}$`,
);

/** A psql rule: `keep` says a quoted value stays (already masked, or the caller's own SQL text). */
interface PsqlEchoRule {
  pattern: RegExp;
  replace: (keep: (value: string) => boolean, match: string, ...groups: string[]) => string;
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

/** The object kinds psql names in a `<kind> "<name>" does not exist` error. */
const PSQL_NAMED_OBJECT_KINDS = [
  'relation',
  'role',
  'schema',
  'function',
  'database',
  'type',
  'collation',
  'sequence',
  'tablespace',
  'extension',
  'operator class',
  'operator family',
  'text search (?:configuration|dictionary|parser|template)',
].join('|');

/** psql error texts that quote the value that failed, so a query that errors never hands back the
 *  data its result would have masked by column name (`SELECT password::int` echoes the password):
 *  a cast (`invalid input syntax for type <t>: "<v>"`, `invalid input value for enum <t>: "<v>"`,
 *  `value "<v>" is out of range for type <t>` and its float form without `value`, `malformed array
 *  literal: "<v>"`, `date/time field value out of range: "<v>"`, `date|timestamp out of range: "<v>"`,
 *  `interval field value out of range: "<v>"`), `to_date`/`to_timestamp` (`invalid value "<v>"
 *  for "<field>"`), JSON input (`Token "<v>" is invalid`, `but found "<v>"`, `JSON data, line N: <v>`)
 *  and a constraint's DETAIL (`Key (<cols>)=(<v>) already exists`, `Failing row contains (<v>)`).
 *  A quoted value runs to the last quote on its line, since psql never escapes one inside it.
 *  `value too long for type ...` quotes nothing. A computed value also comes back through a lookup:
 *  a `reg*` cast or a function taking a name (`nextval`, `has_table_privilege`, `current_setting`,
 *  `timezone`, `encode`, `pg_size_bytes`) quotes it as `<kind> "<v>" does not exist` (a column only
 *  as `column "<v>" of relation`, the `has_column_privilege` form: a bare `column "x" does not exist`
 *  names what the SQL itself wrote), `time zone
 *  "<v>" not recognized`, `unrecognized configuration parameter "<v>"` and kin; a `tsquery`/`xml`
 *  cast as `syntax error in tsquery: "<v>"` or the content line above libxml's caret. Last, the
 *  backstop: on a line psql prefixes (`ERROR:`, `DETAIL:`, `HINT:`, `CONTEXT:`), a value quoted after
 *  `word: "` or `)=(` is masked whatever the text before it says, so a cast nobody listed still masks
 *  rather than leaks. `sql_error`'s fields carry no prefix, so only the listed texts reach those.
 *  A value that repeats a whole token of the caller's own SQL (`ScrubOptions.echoText`) stays: it
 *  names what the SQL wrote, which tells the caller nothing a `WHERE x = '<token>'` would not. */
const PSQL_DATA_ECHO_RULES: PsqlEchoRule[] = [
  {
    pattern: new RegExp(
      String.raw`\b((?:invalid input syntax for type [^:"\n]{1,${MAX_PSQL_TYPE_NAME_CHARS}}|invalid input value for enum [^:"\n]{1,${MAX_PSQL_TYPE_NAME_CHARS}}|malformed (?:array|record|range|multirange) literal|(?:date\/time field value|interval field value|time zone displacement|date|timestamp) out of range): ")([^\n]*)(")`,
      'g',
    ),
    replace: (keep, m, head = '', value = '', close = '') =>
      keep(value) ? m : `${head}${MASK}${close}`,
  },
  {
    pattern: /(\binvalid value ")([^\n]*?)(" for ")|(")([^"\n]*)(" is out of range for type )/g,
    replace: (keep, m, head = '', value = '', close = '', head2 = '', value2 = '', close2 = '') => {
      const [lead, inner, tail] = head.length > 0 ? [head, value, close] : [head2, value2, close2];
      return keep(inner) ? m : `${lead}${MASK}${tail}`;
    },
  },
  {
    pattern: /\b(Token ")([^\n]*)(" is invalid)|(, but found ")([^\n]*)(")/g,
    replace: (keep, m, head = '', value = '', close = '', head2 = '', value2 = '', close2 = '') => {
      const [lead, inner, tail] = head.length > 0 ? [head, value, close] : [head2, value2, close2];
      return keep(inner) ? m : `${lead}${MASK}${tail}`;
    },
  },
  {
    pattern: /\b(JSON data, line \d+: )([^\n]+)/g,
    replace: (keep, m, head = '', value = '') => (keep(value) ? m : `${head}${MASK}`),
  },
  {
    pattern:
      /\b(Key \([^\n]*?\)=\()([^\n]*?)(\) (?:already exists|is not present in table|is still referenced from table|conflicts with existing key))/g,
    replace: (keep, m, head = '', value = '', close = '') =>
      keep(value) ? m : `${head}${MASK}${close}`,
  },
  {
    pattern:
      /\b((?:conflicts with existing key \([^\n]*?\)=|Failing row contains )\()([^\n]*)(\))/g,
    replace: (keep, m, head = '', value = '', close = '') =>
      keep(value) ? m : `${head}${MASK}${close}`,
  },
  {
    pattern: new RegExp(
      String.raw`\b((?:${PSQL_NAMED_OBJECT_KINDS}|time zone) ")([^\n]*?)(")(?=(?: for encoding "[^"\n]*")? (?:does not exist|not recognized))|\b(column ")([^\n]*?)(")(?= of relation "[^"\n]*" does not exist)`,
      'g',
    ),
    replace: (keep, m, head = '', value = '', close = '', head2 = '', value2 = '', close2 = '') => {
      const [lead, inner, tail] = head.length > 0 ? [head, value, close] : [head2, value2, close2];
      return keep(inner) ? m : `${lead}${MASK}${tail}`;
    },
  },
  {
    pattern:
      /\b((?:unrecognized configuration parameter|unrecognized encoding:|invalid (?:source |destination )?encoding name|invalid type name|at or near|syntax error in tsquery:|invalid size:|Invalid size unit:) ")([^\n]*)(")/g,
    replace: (keep, m, head = '', value = '', close = '') =>
      keep(value) ? m : `${head}${MASK}${close}`,
  },
  {
    pattern: /\b(operator does not exist: )([^\n]+)/g,
    replace: (keep, m, head = '', value = '') =>
      keep(value) || OPERATOR_SIGNATURE.test(value) ? m : `${head}${MASK}`,
  },
  {
    pattern: /^((?:DETAIL: {2})?line \d+: [^\n]*\n)([^\n]+)(?=\n[ \t]*\^[ \t]*$)/gm,
    replace: (keep, m, head = '', value = '') => (keep(value) ? m : `${head}${MASK}`),
  },
  {
    pattern: /^((?:psql:\S*\s+)?(?:ERROR|DETAIL|HINT|CONTEXT): {2}[^\n]*?[^\s:]: ")([^\n]*)(")/gm,
    replace: (keep, m, head = '', value = '', close = '') =>
      keep(value) ? m : `${head}${MASK}${close}`,
  },
  {
    pattern:
      /^((?:psql:\S*\s+)?(?:ERROR|DETAIL|HINT|CONTEXT): {2}[^\n]*?\)=\()([^\n]*?)(\))(?=[ .,]|$)/gm,
    replace: (keep, m, head = '', value = '', close = '') =>
      keep(value) ? m : `${head}${MASK}${close}`,
  },
];

/** A stored password verifier, whatever column or key holds it (`SELECT rolpassword AS h FROM
 *  pg_authid` comes back under `h`): Postgres SCRAM-SHA-256 and `md5` + 32 hex as a whole value,
 *  bcrypt `$2a$`/`$2b$`/`$2y$`, argon2, and crypt(3) `$1$`/`$5$`/`$6$` and yescrypt `$y$` (the
 *  `/etc/shadow` default on Debian 11+ and Ubuntu 22.04+, added beside the listed crypt forms).
 *  A `.` ends the token unless a token character follows it, so a verifier closing a sentence
 *  is still whole. */
const PASSWORD_VERIFIER = new RegExp(
  [
    String.raw`SCRAM-SHA-256\$\d+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+`,
    'md5[0-9a-f]{32}',
    String.raw`\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}`,
    String.raw`\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+`,
    String.raw`\$[156]\$(?:rounds=\d+\$)?[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{22,86}`,
    String.raw`\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{1,86}\$[./A-Za-z0-9]{43}`,
  ]
    .map((shape) => String.raw`(?<![\w$])${shape}(?![\w$/+=]|\.[\w$./+=])`)
    .join('|'),
  'g',
);

/** A lone private-key END (its BEGIN cut off) masks the text before it. The END line's own lead
 *  (`path:4:` of a grep match, `web-1  | ` of a log) stays on that line unless it ends in a base64
 *  body chunk, so one line stays one line; with nothing body-like before it the text is unchanged. */
function maskBeforeLoneEnd(match: string, body: string, end: string): string {
  const lineStart = body.lastIndexOf('\n') + 1;
  const above = body.slice(0, lineStart);
  const lead = body.slice(lineStart);
  const leadIsBody = PEM_BODY_CHUNK.test(bareSide(lead).slice(-16));
  if (!HAS_CONTENT.test(above) && !leadIsBody) {
    return match;
  }
  if (leadIsBody) {
    return `${MASK}\n${end}`;
  }
  return `${MASK}\n${lead}${end}`;
}

/** Value shapes that are secrets wherever they appear, independent of any key name. */
const SHAPE_RULES: ShapeRule[] = [
  {
    pattern: new RegExp(String.raw`^((?:(?!-----BEGIN)[\s\S])*?)(-----END ${PEM_LABEL}-----)`, 'g'),
    replace: (m, body = '', end = '') => maskBeforeLoneEnd(m, body, end),
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
    pattern: PASSWORD_VERIFIER,
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
      (isSecretPair(key, value) || SIGNATURE_PARAM.test(key)) && !isMasked(value)
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
      isSecretPair(tag, value) && !isMasked(value) ? `<${tag}>${MASK}</${tag}>` : m,
  },
  {
    pattern:
      /(\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b[^\n]{0,256}?[ \t]-p)([^\s"']+)/g,
    replace: (m, head = '', value = '') => (isMasked(value) ? m : `${head}${MASK}`),
  },
];

/** The alias's own connection identity, from the `ssh -G` the transport already runs to validate
 *  the alias. A port is present only when it is not 22, a hostname only when it is not the alias. */
export interface ConnectionIdentity {
  hostname?: string;
  user?: string;
  port?: string;
}

export interface ScrubOptions {
  /** Keys a `--reveal` already cleared (denylist + reveal-allowlist): their lines are left as-is. */
  revealKeys?: ReadonlySet<string>;
  /** Per-alias extra patterns (reveal-allowlist.toml `[<alias>.scrub] extra_patterns`): every match is masked. */
  extraPatterns?: RegExp[];
  /** Text the caller itself wrote (a `db query` statement): a value a psql error quotes that
   *  repeats one of its whole tokens is the caller's own words and stays visible. */
  echoText?: string;
  /** Exact strings masked wherever they stand as a whole word — the db connection fields an
   *  error echoes (`role "<user>" does not exist`), which an envelope never carries. */
  literals?: string[];
  /** Masked as `<host>`/`<user>`/`<port>` wherever it appears; no per-alias setting turns it off. */
  identity?: ConnectionIdentity;
  /** A run of `ENV_BLOCK_MIN_LINES` or more env-file lines has every value masked, whatever its key
   *  (`deploy run`, whose steps can print a `.env`). */
  maskEnvBlocks?: boolean;
  /** Every other non-loopback, specified IP literal becomes `<ip-N>`, numbered per `scrub` call.
   *  Only the envelope pass sets it (`[<alias>.scrub] reveal_addresses = true` clears it): a file
   *  `files download` writes to disk is the user's own bytes and keeps its addresses. */
  maskAddresses?: boolean;
}

const HOST_MASK = '<host>';
const USER_MASK = '<user>';
const PORT_MASK = '<port>';

const OCTET = String.raw`(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)`;
const IPV4 = String.raw`(?:${OCTET}\.){3}${OCTET}`;
const IPV4_EXACT = new RegExp(`^${IPV4}$`);
const HEX_GROUP = /^[0-9A-Fa-f]{1,4}$/;

/** One pass for both families, so `<ip-N>` numbers follow first appearance. IPv6: two to seven
 *  `:`s between hex groups of at most four digits (an optional dotted IPv4 tail), starting where no
 *  word character, `.` or `:` precedes, or right after a `word:` whose word holds a non-hex letter
 *  (`addr:`, `client_ip:`, `src:`), which no address group can be — `ipv6Groups` decides; a MAC
 *  (six groups, no `::`) and a `12:34:56` time never qualify. IPv4: four octets with no leading
 *  zero, not preceded by a word character or `.` and not followed by one or by `.<digit>` — so
 *  `1.2.3.4.5`, `v10.0.0.1` and `nginx:1.25.3` stay, while `addr:192.0.2.1` is masked. A `/24` or
 *  `:443` after it stays visible. */
const IPV6_CANDIDATE = String.raw`(?:(?<![\w.:])|(?<=[G-Zg-z_][0-9A-Fa-f]{0,${MAX_LABEL_HEX_TAIL_CHARS}}:))([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:\.\d{1,3}){0,3})`;
const ADDRESS_CANDIDATE = new RegExp(
  String.raw`${IPV6_CANDIDATE}|(?<![\w.])(${IPV4})(?![\w]|\.\d)`,
  'g',
);

/** The eight 16-bit groups of an IPv6 literal, or null when it is not one. A `::` form needs a
 *  group of three or more hex digits or an IPv4 tail, so `a::b` and `ab::cd` (Rust and C++ paths)
 *  are not addresses — nor are `::1` and `::`, which are kept anyway. */
function ipv6Groups(text: string): number[] | null {
  let body = text;
  const lastColon = body.lastIndexOf(':');
  const tail = body.slice(lastColon + 1);
  let v4: number[] = [];
  if (tail.includes('.')) {
    if (!IPV4_EXACT.test(tail)) {
      return null;
    }
    const [a = 0, b = 0, c = 0, d = 0] = tail.split('.').map(Number);
    v4 = [a * 256 + b, c * 256 + d];
    body = body.slice(0, lastColon + 1);
    if (!body.endsWith('::')) {
      body = body.slice(0, -1);
    }
  }
  const halves = body.split('::');
  if (halves.length > 2) {
    return null;
  }
  const parts = halves.map((half) => (half.length === 0 ? [] : half.split(':')));
  const groups = parts.flat();
  if (!groups.every((group) => HEX_GROUP.test(group))) {
    return null;
  }
  const present = groups.length + v4.length;
  const values = (list: string[]): number[] => list.map((group) => Number.parseInt(group, 16));
  if (halves.length === 1) {
    return present === 8 ? [...values(groups), ...v4] : null;
  }
  if (present > 7) {
    return null;
  }
  if (v4.length === 0 && !groups.some((group) => group.length >= 3)) {
    return null;
  }
  const [head = [], rest = []] = parts;
  const zeros = new Array<number>(8 - present).fill(0);
  return [...values(head), ...zeros, ...values(rest), ...v4];
}

function isKeptIPv4(address: string): boolean {
  return address.startsWith('127.') || address === '0.0.0.0';
}

function isKeptIPv6(groups: number[]): boolean {
  return groups.slice(0, 7).every((value) => value === 0) && (groups[7] ?? 0) <= 1;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const GAP = `[ \\t]{0,${MAX_IDENTITY_GAP_CHARS}}`;
/** Between an identity keyword and its value: `=`/`:` with blanks around it, or blanks alone,
 *  either side optionally quoted (`user=x`, `"user": "x"`, `for user "x"`, `-l x`, `-p2222`). */
const IDENTITY_SEP = `["']?(?:${GAP}[=:]${GAP}|${GAP})["']?`;

/** One identity rule: `mask` gets the match, its groups (absent ones as `''`), its offset and the
 *  whole string, and returns the match itself to leave it alone. `inKeys` lets it rewrite an object
 *  key — only for shapes a fixed field name never has (a dotted hostname, an IP, `2222/tcp`). */
interface IdentityRule {
  pattern: RegExp;
  mask: (match: string, groups: string[], offset: number, whole: string) => string;
  inKeys: boolean;
}

const leadThen =
  (mask: string) =>
  (_match: string, groups: string[]): string =>
    `${groups.find((group) => group.length > 0) ?? ''}${mask}`;

/** Between a host keyword and a short hostname: `=`/`:` or at least one blank, so `toweb1` is no context. */
const HOST_SEP = `["']?(?:${GAP}[=:]${GAP}|[ \\t]{1,${MAX_IDENTITY_GAP_CHARS}})["']?`;
/** Options between `ssh` and its destination (`ssh -l opsuser -p 2222 web1`): a dashed flag and, when
 *  the next word does not start with a dash, its value. Eight is more than any real command line. */
const SSH_OPTIONS = `(?:[ \\t]{1,${MAX_IDENTITY_GAP_CHARS}}-\\w+(?:[ \\t]{1,${MAX_IDENTITY_GAP_CHARS}}[^\\s-]\\S*)?){0,8}`;
/** A syslog line's own host field: after a BSD (`Nov 27 10:00:00`) or RFC 3339 timestamp at line
 *  start, the RFC 3339 one optionally behind an RFC 5424 `<PRI>VERSION ` header (`<34>1 `). */
const SYSLOG_STAMP = String.raw`^(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d|(?:<\d{1,3}>\d{1,2} )?\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:?\d\d)) `;

/** The alias hostname. An IPv6 one is compared by value, so its expanded and compressed forms are
 *  both `<host>`. A dotless one under `MIN_BARE_HOSTNAME_CHARS` (`web1`, `db`) is masked only in a
 *  host context — `host X`, `hostname X`, `to X`, `ssh [options] X`, `@X`, `X:<port>`, `[X]:<port>`,
 *  an scp/rsync remote path `X:/path` or `X:~/path`, a syslog line's host field — and everywhere
 *  else stays, being too common a word; any longer or dotted one is masked wherever it stands. */
function hostnameRule(hostname: string): IdentityRule | null {
  const escaped = escapeRegExp(hostname);
  if (IPV4_EXACT.test(hostname)) {
    return {
      pattern: new RegExp(String.raw`(?<![\w.])${escaped}(?![\w]|\.\d)`, 'g'),
      mask: () => HOST_MASK,
      inKeys: true,
    };
  }
  if (hostname.includes(':')) {
    const own = ipv6Groups(hostname);
    if (own !== null) {
      return {
        pattern: new RegExp(IPV6_CANDIDATE, 'g'),
        mask: (match, [candidate = ''], offset, whole) => {
          const groups = /[\w:]/.test(whole[offset + match.length] ?? '')
            ? null
            : ipv6Groups(candidate);
          return groups?.every((value, i) => value === own[i]) ? HOST_MASK : match;
        },
        inKeys: true,
      };
    }
    return {
      pattern: new RegExp(String.raw`(?<![\w.:])${escaped}(?![\w:])`, 'gi'),
      mask: () => HOST_MASK,
      inKeys: true,
    };
  }
  if (!hostname.includes('.') && hostname.length < MIN_BARE_HOSTNAME_CHARS) {
    return {
      pattern: new RegExp(
        String.raw`((?:^|[^\w-])(?:host(?:name)?|to|ssh${SSH_OPTIONS})${HOST_SEP}|@|${SYSLOG_STAMP})${escaped}(?![\w-]|\.[\w-])|(?<![\w.-])${escaped}(?=:\d{1,5}(?![\d.])|:[/~])|(?<=\[)${escaped}(?=\]:\d{1,5}(?!\d))`,
        'gim',
      ),
      mask: leadThen(HOST_MASK),
      inKeys: false,
    };
  }
  return {
    pattern: new RegExp(String.raw`(?<![\w.-])${escaped}(?![\w-]|\.[\w-])`, 'gi'),
    mask: () => HOST_MASK,
    inKeys: hostname.includes('.'),
  };
}

/** Login names that are also ordinary words in logs, package trees, unit names and shell loops
 *  (`app@2.0.0`, `app@1000.service`, `for app in ...`): the cloud-image defaults, role accounts and
 *  service accounts. Such a user is masked only where it names who connects; any other user is
 *  distinctive and masked wherever it stands as a whole word. */
const COMMON_USER_NAMES = new Set([
  'root',
  'admin',
  'administrator',
  'user',
  'ubuntu',
  'debian',
  'centos',
  'fedora',
  'rocky',
  'almalinux',
  'ec2-user',
  'azureuser',
  'opc',
  'core',
  'vagrant',
  'bitnami',
  'app',
  'www',
  'www-data',
  'web',
  'api',
  'deploy',
  'deployer',
  'git',
  'dev',
  'test',
  'guest',
  'ops',
  'devops',
  'server',
  'service',
  'node',
  'docker',
  'postgres',
  'mysql',
  'nginx',
  'backup',
  'data',
  'worker',
  'ansible',
]);

const SYSTEMD_UNIT_SUFFIX =
  /\.(?:service|socket|timer|target|mount|automount|path|slice|scope|device|swap)$/;

/** npm dist-tags (`app@latest`) and package protocols (`app@npm:`, `app@workspace:*`): after `@`
 *  they name a package version, not a host. */
const PACKAGE_DIST_TAG = /^(?:latest|next|beta|alpha|canary|rc|stable|nightly|experimental|lts)$/i;
const PACKAGE_PROTOCOL = /^(?:npm|workspace|file|link|portal|patch|catalog|jsr|github)$/i;

/** What follows `user@` when it is a login: `<host>`, a `[v6]` literal, an IPv4 address or a
 *  letter-led hostname — never a version (`app@2.0.0`, `app@v2.1.0`), a dist-tag (`app@latest`), a
 *  package protocol (`app@npm:core`), a digest (`app@sha256:`) or a unit instance
 *  (`getty@tty1.service`). */
function isHostAfterAt(token: string): boolean {
  if (token.startsWith(HOST_MASK) || token.startsWith('[')) {
    return true;
  }
  const head = (/^[\w.-]+/.exec(token)?.[0] ?? '').replace(/\.+$/, '');
  if (IPV4_EXACT.test(head)) {
    return true;
  }
  if (!/^[A-Za-z]/.test(head)) {
    return false;
  }
  if (/^sha\d+$/i.test(head) && token[head.length] === ':') {
    return false;
  }
  if (PACKAGE_DIST_TAG.test(head) || /^v\d+(?:\.\d+)*$/i.test(head)) {
    return false;
  }
  if (token[head.length] === ':' && PACKAGE_PROTOCOL.test(head)) {
    return false;
  }
  return !SYSTEMD_UNIT_SUFFIX.test(head);
}

/** How far a sudo log line may run from `<user> :` to its `TTY=`/`PWD=`/`COMMAND=` field: sudo's
 *  own line is far shorter, and the bound keeps the lookahead linear. */
const MAX_SUDO_LINE_CHARS = 512;

/** The alias user. A distinctive one is masked as a whole word everywhere (`ls -l`, `ps`, `/home/x`,
 *  `id`, sudo logs). A `COMMON_USER_NAMES` one only where it names who connects: `user@<host-like>`,
 *  a URL's `://user:`, `-l user`, `User user`, `user=user`, `"user":"user"`, `login: user`, sshd's
 *  `for [invalid user ]user from`, sudo's `user : TTY=... ; PWD=...` and a `/home/user` path. */
function userRule(user: string): IdentityRule | null {
  if (user.length < MIN_MASKED_USER_CHARS) {
    return null;
  }
  const escaped = escapeRegExp(user);
  if (!COMMON_USER_NAMES.has(user.toLowerCase())) {
    return {
      pattern: new RegExp(String.raw`(?<![\w.-])${escaped}(?![\w-]|\.[\w-])`, 'gi'),
      mask: () => USER_MASK,
      inKeys: false,
    };
  }
  const blanks = `[ \\t]{1,${MAX_IDENTITY_GAP_CHARS}}`;
  return {
    pattern: new RegExp(
      String.raw`((?:^|[^\w-])(?:-l|user(?:name)?|login|logname)${IDENTITY_SEP})${escaped}(?![\w-]|\.[\w-])|((?:^|[^\w-])for${blanks}(?:invalid${blanks}user${blanks})?)${escaped}(?=${blanks}from\b)|(?<![\w.-])${escaped}(?=@([^\s"']{0,${MAX_HOSTNAME_CHARS}}))|(?<=:\/\/)${escaped}(?=:)|(?<![\w.-])${escaped}(?=${blanks}:[ \t][^\n]{0,${MAX_SUDO_LINE_CHARS}}?\b(?:TTY|PWD|COMMAND)=)|(?<=\/home\/)${escaped}(?![\w.-])`,
      'gim',
    ),
    mask: (match, [keyword = '', sshd = '', afterAt = ''], offset, whole) => {
      if (keyword.length > 0 || sshd.length > 0) {
        return `${keyword}${sshd}${USER_MASK}`;
      }
      if (whole[offset + match.length] === '@' && !isHostAfterAt(afterAt)) {
        return match;
      }
      return USER_MASK;
    },
    inKeys: false,
  };
}

/** A name that holds a port: `SSH_PORT`, `PGPORT`, `ssh_port`, `db.port`, `HostPort`, `sshPort`. */
const GLUED_PORT_KEY = String.raw`(?<![\w.-])[\w.-]*(?:PORT|[_.-]port|[a-z0-9]Port)`;

function isPortKey(key: string): boolean {
  return new RegExp(`^${GLUED_PORT_KEY}$`).test(key) || /^port$/i.test(key);
}

/** The alias port where it is one: `host:port`, docker's `:::port` and ss's `*:port` listeners,
 *  `-p port`/`-P port`, `port port`, `Port=port`, a key holding a port (`SSH_PORT=port`,
 *  `"HostPort":"port"`), and `port/tcp`/`port/udp`; the last also in object keys (`docker
 *  inspect`'s `"2222/tcp"`). */
function portRules(port: string): IdentityRule[] {
  if (!/^\d+$/.test(port)) {
    return [];
  }
  return [
    {
      pattern: new RegExp(
        String.raw`((?:[\w\]>]:|:::|\*:|(?:^|[^\w-])(?:-p|-P|[Pp][Oo][Rr][Tt])${IDENTITY_SEP}|${GLUED_PORT_KEY}["']?${GAP}[=:]${GAP}["']?))${port}(?!\d)`,
        'gm',
      ),
      mask: leadThen(PORT_MASK),
      inKeys: false,
    },
    {
      pattern: new RegExp(String.raw`(?<![\w.])${port}(?=\/(?:tcp|udp))`, 'g'),
      mask: () => PORT_MASK,
      inKeys: true,
    },
  ];
}

interface AddressMasker {
  /** Masks one string; `keyOnly` (an object key) runs only the rules marked `inKeys`, so a fixed
   *  field name can never be rewritten. */
  apply: (text: string, keyOnly: boolean) => ScrubResult<string>;
  /** A JSON string value that is exactly the alias port under a port-holding key
   *  (`{"HostPort": "2222"}`) becomes `<port>`; a numeric one stays a number. */
  maskPortValue: (key: string, value: string) => string;
}

/** Rule 1 (the alias's identity) then rule 2 (every other address), sharing one `<ip-N>` table. */
function createAddressMasker(options: ScrubOptions): AddressMasker | null {
  const identity = options.identity ?? {};
  const rules: IdentityRule[] = [
    identity.hostname ? hostnameRule(identity.hostname) : null,
    identity.user ? userRule(identity.user) : null,
    ...(identity.port ? portRules(identity.port) : []),
  ].filter((rule): rule is IdentityRule => rule !== null);
  const maskAddresses = options.maskAddresses === true;
  if (rules.length === 0 && !maskAddresses) {
    return null;
  }
  const tokens = new Map<string, string>();
  const tokenFor = (address: string): string => {
    const key = address.toLowerCase();
    let token = tokens.get(key);
    if (token === undefined) {
      token = `<ip-${tokens.size + 1}>`;
      tokens.set(key, token);
    }
    return token;
  };
  const maskOneAddress = (
    match: string,
    v6: string | undefined,
    v4: string | undefined,
    offset: number,
    whole: string,
  ): string => {
    if (v4 !== undefined) {
      return isKeptIPv4(v4) ? match : tokenFor(v4);
    }
    const candidate = v6 ?? '';
    const next = whole[offset + match.length] ?? '';
    const groups = /[\w:]/.test(next) ? null : ipv6Groups(candidate);
    if (groups === null) {
      const tail = /(?<=:)(?:\d{1,3}\.){3}\d{1,3}$/.exec(candidate)?.[0];
      if (tail !== undefined && IPV4_EXACT.test(tail) && !isKeptIPv4(tail) && !/[\w:]/.test(next)) {
        return `${candidate.slice(0, -tail.length)}${tokenFor(tail)}`;
      }
      return match;
    }
    return isKeptIPv6(groups) ? match : tokenFor(candidate);
  };
  return {
    apply: (text, keyOnly) => {
      let out = text;
      let count = 0;
      for (const rule of rules) {
        if (keyOnly && !rule.inKeys) {
          continue;
        }
        out = out.replace(rule.pattern, (...args: unknown[]) => {
          const whole = args.at(-1) as string;
          const offset = args.at(-2) as number;
          const [match = '', ...groups] = args
            .slice(0, -2)
            .map((arg) => (typeof arg === 'string' ? arg : ''));
          const masked = rule.mask(match, groups, offset, whole);
          if (masked !== match) {
            count += 1;
          }
          return masked;
        });
      }
      if (maskAddresses) {
        out = out.replace(
          ADDRESS_CANDIDATE,
          (
            match: string,
            v6: string | undefined,
            v4: string | undefined,
            offset: number,
            whole: string,
          ) => {
            const masked = maskOneAddress(match, v6, v4, offset, whole);
            if (masked !== match) {
              count += 1;
            }
            return masked;
          },
        );
      }
      return { value: out, count };
    },
    maskPortValue: (key, value) =>
      identity.port !== undefined && value === identity.port && isPortKey(key) ? PORT_MASK : value,
  };
}

export interface ScrubResult<T> {
  value: T;
  count: number;
}

function isMasked(value: string): boolean {
  const bare = value.replace(/^["']|["']$/g, '');
  return bare === MASK || bare === ENV_MASK;
}

/** Whether `value` stands in `text` as a whole token: no word character or `$` on either side. */
function isWholeTokenOf(value: string, text: string): boolean {
  if (value.length === 0) {
    return false;
  }
  for (let at = text.indexOf(value); at !== -1; at = text.indexOf(value, at + 1)) {
    if (!/[\w$]/.test(text[at - 1] ?? '') && !/[\w$]/.test(text[at + value.length] ?? '')) {
      return true;
    }
  }
  return false;
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

/** `KEYED_INLINE` over the text. A pair whose key is not secret is not consumed: the search resumes
 *  at its value, so an assignment nested inside it (`JAVA_OPTS="-Dspring.datasource.password=v"`,
 *  `CMD=--password=v`, `x=api_key=v`) is still found. Each level of nesting rescans its own value,
 *  so the depth is capped at `MAX_NESTED_ASSIGNMENT_DEPTH`: an `a=b=c=...` chain stays linear. */
function maskKeyedInline(text: string, revealKeys: ReadonlySet<string>): ScrubResult<string> {
  const pattern = new RegExp(KEYED_INLINE.source, 'g');
  const openValueEnds: number[] = [];
  let out = '';
  let pos = 0;
  let count = 0;
  for (let match = pattern.exec(text); match !== null; match = pattern.exec(text)) {
    const [whole, q = '', key = '', sep = '', value = ''] = match;
    const end = match.index + whole.length;
    while (openValueEnds.length > 0 && match.index >= (openValueEnds.at(-1) ?? 0)) {
      openValueEnds.pop();
    }
    if (!isSecretPair(key, value) || revealKeys.has(key) || isMasked(value)) {
      if (value.length > 0 && openValueEnds.length < MAX_NESTED_ASSIGNMENT_DEPTH) {
        openValueEnds.push(end);
        pattern.lastIndex = end - value.length;
      }
      continue;
    }
    out += `${text.slice(pos, match.index)}${q}${key}${q}${sep}${maskedValue(value, MASK)}`;
    pos = end;
    count += 1;
  }
  return { value: `${out}${text.slice(pos)}`, count };
}

/** A base64 or base64url run (wrapped lines included, as `base64` prints them) long enough to hold
 *  a `KEY=value` line. */
const BASE64_BLOB =
  /(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}(?:\r?\n[A-Za-z0-9+/_-]{2,})*={0,2}(?![A-Za-z0-9+/_=-])/g;
/** Share of a decoded blob that may be non-text before it counts as binary (a key, a digest). */
const MAX_BINARY_SHARE = 0.1;

/** Whether a base64 blob decodes to text holding anything the scrubber masks — a secret, the alias
 *  identity, an address the envelope would number: an op that hands back a file base64-encoded must
 *  not carry what the plain text could not. Binary payloads (public keys, digests, an identifier that
 *  only looks like base64) are left alone. */
function hidesSecret(
  blob: string,
  options: ScrubOptions,
  addresses: AddressMasker | null,
): boolean {
  const decoded = Buffer.from(
    blob.replace(/\r?\n/g, '').replaceAll('-', '+').replaceAll('_', '/'),
    'base64',
  ).toString('utf8');
  if (decoded.length === 0) {
    return false;
  }
  const binary = decoded.replace(/[\t\n\r\x20-\x7e -￼]/g, '').length;
  if (binary / decoded.length > MAX_BINARY_SHARE) {
    return false;
  }
  return scrubTextWith(decoded, options, addresses).count > 0;
}

/** One env-file assignment as a whole line: `[export ]KEY=value`, blanks allowed around `=`. */
const ENV_BLOCK_LINE = new RegExp(
  String.raw`^([ \t]*(?:export[ \t]+)?${KEY_NAME}[ \t]*=[ \t]*)(.*)$`,
);
/** Lines an env file holds between its assignments, which do not end a run. */
const ENV_BLOCK_FILLER = /^[ \t]*(?:#.*)?$/;

/** Every value in a run of at least `ENV_BLOCK_MIN_LINES` assignment lines, whatever its key: the
 *  key-name rules alone leave `SPACED = value` readable, and in a printed `.env` any key can hold
 *  a secret. A shorter run is left to those rules. */
function maskEnvBlocks(text: string): ScrubResult<string> {
  const lines = text.split('\n');
  let count = 0;
  let run: number[] = [];
  const flush = (): void => {
    if (run.length >= ENV_BLOCK_MIN_LINES) {
      for (const index of run) {
        const match = ENV_BLOCK_LINE.exec(lines[index] ?? '');
        const value = match?.[2] ?? '';
        if (match !== null && value.trim().length > 0 && !isMasked(value.trim())) {
          lines[index] = `${match[1]}${maskedValue(value.trim(), ENV_MASK)}`;
          count += 1;
        }
      }
    }
    run = [];
  };
  lines.forEach((line, index) => {
    if (ENV_BLOCK_LINE.test(line)) {
      run.push(index);
    } else if (!ENV_BLOCK_FILLER.test(line)) {
      flush();
    }
  });
  flush();
  return count === 0 ? { value: text, count } : { value: lines.join('\n'), count };
}

/** Masks every secret in one string, then its addresses; `count` is how many values were replaced. */
export function scrubText(text: string, options: ScrubOptions = {}): ScrubResult<string> {
  return scrubTextWith(text, options, createAddressMasker(options));
}

function scrubTextWith(
  text: string,
  options: ScrubOptions,
  addresses: AddressMasker | null,
): ScrubResult<string> {
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
  const echoText = options.echoText ?? '';
  const keepPsqlValue = (value: string): boolean =>
    isMasked(value) || isWholeTokenOf(value, echoText);
  for (const rule of PSQL_DATA_ECHO_RULES) {
    out = out.replace(rule.pattern, (...args: unknown[]) => {
      const groups = args.slice(0, -2).map((arg) => (typeof arg === 'string' ? arg : ''));
      const [match = '', ...rest] = groups;
      const replaced = rule.replace(keepPsqlValue, match, ...rest);
      if (replaced !== match) {
        count += 1;
      }
      return replaced;
    });
  }
  if (options.maskEnvBlocks === true) {
    const blocks = maskEnvBlocks(out);
    out = blocks.value;
    count += blocks.count;
  }
  const [protectedText, kept] = protectRevealedLines(out, revealKeys);
  out = protectedText;
  out = out.replace(
    KEYED_LINE,
    (match, lead: string, q: string, key: string, sep: string, value: string) => {
      if (
        !isSecretPair(key, value) ||
        revealKeys.has(key) ||
        value.length === 0 ||
        isMasked(value)
      ) {
        return match;
      }
      count += 1;
      return `${lead}${q}${key}${q}${sep}${maskedValue(value, MASK)}`;
    },
  );
  const inline = maskKeyedInline(out, revealKeys);
  out = inline.value;
  count += inline.count;
  for (const pattern of [KEYED_SUBSCRIPT, KEYED_CALL_ARG]) {
    out = out.replace(
      pattern,
      (match, lead: string, q: string, key: string, sep: string, value: string) => {
        if (!isSecretPair(key, value) || revealKeys.has(key) || isMasked(value)) {
          return match;
        }
        count += 1;
        return `${lead}${q}${key}${q}${sep}${maskedValue(value, MASK)}`;
      },
    );
  }
  out = out.replace(
    KEYED_ADJACENT,
    (match, dashes: string, key: string, gap: string, value: string) => {
      if (!isSecretPair(key, value) || revealKeys.has(key)) {
        return match;
      }
      count += 1;
      return `${dashes}${key}${gap}${MASK}`;
    },
  );
  out = out.replace(
    FLAG_SPACED,
    (match, dashes: string, key: string, gap: string, value: string) => {
      if (!isSecretPair(key, value) || revealKeys.has(key) || isMasked(value)) {
        return match;
      }
      count += 1;
      return `${dashes}${key}${gap}${maskedValue(value, MASK)}`;
    },
  );

  if (kept.length > 0) {
    out = out.replace(/\uE000(\d+)\uE001/g, (_m, index: string) => kept[Number(index)] ?? '');
  }
  out = out.replace(BASE64_BLOB, (blob) => {
    if (!hidesSecret(blob, options, addresses)) {
      return blob;
    }
    count += 1;
    return MASK;
  });
  if (addresses !== null) {
    const masked = addresses.apply(out, false);
    out = masked.value;
    count += masked.count;
  }
  return { value: out, count };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Walks any shaped payload: every string goes through `scrubText`, and every string or number
 * under a secret key name (`{"password": 123}`, `{"tokens": ["x"]}`, `{"password_hash": {...}}`
 * from a `db query` row) is masked whole, at any depth; under a joined-`pass` name (`bypass`) only
 * a non-boolean value is. A string that is exactly the alias port under a port-holding key becomes
 * `<port>`. Object keys get only the rules no fixed field name can match (a `docker inspect` map
 * keyed by IP or by `2222/tcp`). One `<ip-N>` table spans the whole value, so the same
 * address carries the same token in `data` and `error`. Returns a copy; the input is never mutated.
 */
export function scrub<T>(value: T, options: ScrubOptions = {}): ScrubResult<T> {
  let count = 0;
  const revealKeys = options.revealKeys ?? new Set<string>();
  const underSecret = (key: string, child: unknown): boolean => {
    if (revealKeys.has(key)) {
      return false;
    }
    if (isSecretKey(key)) {
      return true;
    }
    const flag =
      typeof child === 'boolean' ||
      ((typeof child === 'string' || typeof child === 'number') && isBooleanWord(String(child)));
    return isJoinedPassKey(key) && !flag;
  };
  const addresses = createAddressMasker(options);
  const maskKey = (key: string): string => {
    if (addresses === null) {
      return key;
    }
    const masked = addresses.apply(key, true);
    count += masked.count;
    return masked.value;
  };
  const walk = (node: unknown, secret: boolean, key?: string): unknown => {
    if (typeof node === 'string') {
      if (secret && node.length > 0 && node !== MASK) {
        count += 1;
        return MASK;
      }
      if (addresses !== null && key !== undefined) {
        const port = addresses.maskPortValue(key, node);
        if (port !== node) {
          count += 1;
          return port;
        }
      }
      const result = scrubTextWith(node, options, addresses);
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
        copy[maskKey(childKey)] = walk(child, secret || underSecret(childKey, child), childKey);
      }
      return copy;
    }
    return node;
  };
  const scrubbed = walk(value, false) as T;
  return { value: scrubbed, count };
}

/** Output built outside `executeOp` (setup results, `doctor`, the CLI's argument-error and catch
 *  envelopes): no alias identity is known there, so the secret rules and rule 2 (every non-loopback
 *  IP becomes `<ip-N>`) run over the whole value, keys and header fields included. */
export function scrubLocalOutput<T>(value: T): ScrubResult<T> {
  return scrub(value, { maskAddresses: true });
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

const prefixShape = (prefix: string): string => prefix.replace(/\d+/g, '0');

/** Longest run a key body line holds: PEM wraps at 64 columns, OpenSSH keys at 70. A longer run
 *  ending a line is something else (a JWT, a minified blob) and is never read as one. */
const MAX_PEM_BODY_LINE_CHARS = 70;
/** How far past the END line's own prefix a line's prefix may run and still be compared with it
 *  (a timestamp's digit runs vary in length: Go trims trailing zeros of its nanoseconds). */
const MAX_PREFIX_SLACK_CHARS = 64;

const isBase64Char = (code: number): boolean =>
  (code >= 65 && code <= 90) ||
  (code >= 97 && code <= 122) ||
  (code >= 48 && code <= 57) ||
  code === 43 ||
  code === 47;

/** `line` split into a log prefix and the base64 run that ends it (`=` padding allowed at its end;
 *  trailing blanks and `PEM_MARKER_EDGE` characters ignored), or null when no run of at most
 *  `MAX_PEM_BODY_LINE_CHARS` ends it. Scans back from the end only, so a long line costs no more
 *  than a short one. */
function splitBodyLine(line: string): { prefix: string; body: string } | null {
  let end = line.length;
  while (end > 0 && /[\s"',;)}\]]/.test(line[end - 1] ?? '')) {
    end -= 1;
  }
  let start = end;
  while (start > 0 && end - start < 2 && line[start - 1] === '=') {
    start -= 1;
  }
  const padding = end - start;
  while (start > 0 && isBase64Char(line.charCodeAt(start - 1))) {
    start -= 1;
    if (end - start > MAX_PEM_BODY_LINE_CHARS) {
      return null;
    }
  }
  if (end - start - padding === 0) {
    return null;
  }
  return { prefix: line.slice(0, start), body: line.slice(start, end) };
}

/** Whether `line` was written under the log prefix whose digit-collapsed shape is `shape`. */
function sameWriter(line: string, shape: string, prefixLength: number): boolean {
  return prefixShape(line.slice(0, prefixLength + MAX_PREFIX_SLACK_CHARS)).startsWith(shape);
}

/** The lines a lone END (its BEGIN cut off) masks, or null when it is not one. When the marker is
 *  the whole line or ends a base64 body on it, that is every line since `bodyStart`. When it carries
 *  a log prefix (`web-1  | `, `<ts> INFO `, `time=<ts> msg=`), it is the base64 body lines that same
 *  prefix wrote above it, looking past other writers' lines (another compose service, a WARN): the
 *  last body line may be short, every one above it holds a full chunk, and the first line of that
 *  writer that is not a body line ends the search. Prefixes compare with digit runs collapsed, so a
 *  ticking timestamp of varying length still matches. `must end with -----END RSA PRIVATE KEY-----`
 *  is prose about a key. */
function lonePemEndBody(lines: readonly string[], i: number, bodyStart: number): number[] | null {
  const line = lines[i] ?? '';
  const end = PEM_END_LINE.exec(line);
  if (!end) {
    return null;
  }
  const prefix = line.slice(0, end.index);
  const before = bareSide(prefix);
  const after = bareSide(line.slice(end.index + end[0].length));
  if (!PEM_MARKER_EDGE.test(after)) {
    return null;
  }
  if (PEM_MARKER_EDGE.test(before) || PEM_BODY_CHUNK.test(before.slice(-16))) {
    return Array.from({ length: i - bodyStart }, (_, k) => bodyStart + k);
  }
  const shape = prefixShape(prefix);
  const body: number[] = [];
  let fullChunk = false;
  const stop = Math.max(bodyStart, i - MAX_PEM_LONE_END_SCAN_LINES);
  for (let j = i - 1; j >= stop; j -= 1) {
    const candidate = lines[j] ?? '';
    const split = splitBodyLine(candidate);
    const ownPrefix =
      split !== null &&
      split.prefix.length <= prefix.length + MAX_PREFIX_SLACK_CHARS &&
      prefixShape(split.prefix) === shape;
    if (ownPrefix) {
      const length = split.body.replace(/=+$/, '').length;
      if (body.length > 0 && length < 16) {
        break;
      }
      fullChunk = fullChunk || length >= 16;
      body.push(j);
      continue;
    }
    if (sameWriter(candidate, shape, prefix.length)) {
      break;
    }
  }
  return fullChunk ? body : null;
}

/** For output already split into lines (`files tail`, `logs *`), where no single string holds
 *  both ends of a PEM block: every line between a private-key BEGIN and its END is masked, and a
 *  lone END (its BEGIN cut off by `-n`) masks the body before it (`lonePemEndBody`). A line that
 *  only mentions a marker in prose does neither. */
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
    const body = lonePemEndBody(lines, i, bodyStart);
    if (body !== null) {
      for (const j of body) {
        out[j] = MASK;
      }
      bodyStart = i + 1;
    }
  }
  return out;
}

/** Full-width key body lines (64 or 70 base64 characters, no padding). */
const PEM_CHUNK_WIDTHS = new Set([64, 70]);
const PUBLIC_PEM_BEGIN = /-----BEGIN (?![A-Z0-9 ]*PRIVATE KEY)[A-Z0-9 ]+-----/;
const ANY_PEM_END = /-----END [A-Z0-9 ]+-----/;
const HEX_ONLY = /^[0-9A-Fa-f]+$/;

/** A key body line with no marker around it at all: a `logs *` window (`--since`/`--until`) or
 *  `--grep` can keep body lines and drop both the BEGIN and the END. Any line that ends in a
 *  full-width base64 chunk (64 or 70 characters, nothing but a blank, `=`, `|`, `:` or a quote
 *  before it, mixed digits and letters rather than a hex digest) is masked, and so is the short
 *  last body line right below one under the same prefix. Lines inside a public block (`BEGIN
 *  CERTIFICATE`) stay. Run after `maskPemLines`, on log output only: a cert body cut off from its
 *  markers is masked too, which fails safe. */
export function maskPemBodyChunks(lines: readonly string[]): string[] {
  const out = [...lines];
  let inPublicBlock = false;
  let chunkShape: string | null = null;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    if (inPublicBlock) {
      inPublicBlock = !ANY_PEM_END.test(line);
      continue;
    }
    if (PUBLIC_PEM_BEGIN.test(line)) {
      inPublicBlock = !ANY_PEM_END.test(line.slice(line.search(PUBLIC_PEM_BEGIN) + 11));
      chunkShape = null;
      continue;
    }
    const split = splitBodyLine(line);
    const lead = split?.prefix.at(-1);
    if (split === null || (lead !== undefined && !/[\s=|:"']/.test(lead))) {
      chunkShape = null;
      continue;
    }
    const full =
      PEM_CHUNK_WIDTHS.has(split.body.length) &&
      !split.body.includes('=') &&
      !HEX_ONLY.test(split.body);
    if (full) {
      out[i] = MASK;
      chunkShape = prefixShape(split.prefix);
      continue;
    }
    if (chunkShape !== null && prefixShape(split.prefix) === chunkShape) {
      out[i] = MASK;
    }
    chunkShape = null;
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
