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
const SECRET_NAME_ENDINGS = ['KEY', 'PASS', 'DSN', 'URL', 'URI'];
const SECRET_NAME_SEGMENTS = new Set(SECRET_NAME_ENDINGS);

/** A key name whose value is a secret: the reveal denylist, a name containing a secret word,
 *  or a name ending in (or having a `_`/`.`/`-` segment equal to) KEY/PASS/DSN/URL/URI.
 *  `PORT`, `NODE_ENV` and `DB_HOST` are not — a host is not a secret by default. */
export function isSecretKey(name: string): boolean {
  if (REVEAL_DENYLIST_PATTERNS.some((pattern) => pattern.test(name))) {
    return true;
  }
  const upper = name.toUpperCase();
  if (SECRET_NAME_FRAGMENTS.some((fragment) => upper.includes(fragment))) {
    return true;
  }
  if (SECRET_NAME_ENDINGS.some((ending) => upper.endsWith(ending))) {
    return true;
  }
  return upper.split(/[_.-]/).some((segment) => SECRET_NAME_SEGMENTS.has(segment));
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

/** `[export ]KEY=value` at line start — the env-file shape `maskEnvContent` masks wholesale. */
const ENV_ASSIGNMENT = new RegExp(
  String.raw`^([ \t]*(?:export[ \t]+)?)(${KEY_NAME})([ \t]*=[ \t]*)(${LINE_VALUE})`,
  'gm',
);

/** `KEY=value`, `export KEY=value`, `key: value`, `"key": "value"`, `- key: value` at line start. */
const KEYED_LINE = new RegExp(
  String.raw`^([ \t]*(?:-[ \t]+)?(?:export[ \t]+)?)(["']?)(${KEY_NAME})\2([ \t]*[=:][ \t]*)(${LINE_VALUE})`,
  'gm',
);

/** The same pair anywhere in a line (`... password=x&user=y`, `{"token":"x"}`, `--secret=x`). */
const KEYED_INLINE = new RegExp(
  String.raw`(?<![\w.$])(["']?)(${KEY_NAME})\1([ \t]*[=:][ \t]*)("(?:[^"\\\n]|\\.)*"|'[^'\n]*'|[^\s"',;&<>)}\]]+)`,
  'g',
);

/** A long base64/hex run right after a secret-ish word with only whitespace between (`--token <v>`). */
const KEYED_ADJACENT = new RegExp(
  String.raw`(?<![\w.$])(-{0,2})(${KEY_NAME})([ \t]+)([A-Za-z0-9+/_-]{32,}={0,2})(?![\w+/=-])`,
  'g',
);

interface ShapeRule {
  pattern: RegExp;
  replace: (match: string, ...groups: string[]) => string;
}

const PEM_LABEL = '[A-Z0-9 ]*PRIVATE KEY';

/** Value shapes that are secrets wherever they appear, independent of any key name. */
const SHAPE_RULES: ShapeRule[] = [
  {
    pattern: new RegExp(
      String.raw`(-----BEGIN (${PEM_LABEL})-----)[\s\S]*?(-----END \2-----)`,
      'g',
    ),
    replace: (_m, begin = '', _label, end = '') => `${begin}\n${MASK}\n${end}`,
  },
  {
    pattern: new RegExp(String.raw`(-----BEGIN ${PEM_LABEL}-----)(?![\s\S]*-----END)[\s\S]*$`, 'g'),
    replace: (_m, begin = '') => `${begin}\n${MASK}`,
  },
  {
    pattern: new RegExp(String.raw`^(?:(?!-----BEGIN)[\s\S])*?(-----END ${PEM_LABEL}-----)`, 'g'),
    replace: (_m, end = '') => `${MASK}\n${end}`,
  },
  {
    pattern: /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+/g,
    replace: () => MASK,
  },
  {
    pattern:
      /(?<![\w-])(?:sk-[A-Za-z0-9_-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,})/g,
    replace: () => MASK,
  },
  {
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    replace: () => MASK,
  },
  {
    pattern: /\b([a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:)([^\s@/?#]+)(@)/gi,
    replace: (_m, head = '', _password, at = '') => `${head}${MASK}${at}`,
  },
  {
    pattern:
      /\b(Authorization["']?[ \t]*[:=][ \t]*["']?(?:Basic|Digest|Token)[ \t]+)([^\s"',;]+)/gi,
    replace: (_m, head = '') => `${head}${MASK}`,
  },
  {
    pattern: /\b(Bearer[ \t]+)([A-Za-z0-9._~+/-]+=*)/g,
    replace: (_m, head = '') => `${head}${MASK}`,
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

/** Lines assigning a revealed key are lifted out before any rule runs and put back after. */
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
  const [protectedText, kept] = protectRevealedLines(text, revealKeys);
  let out = protectedText;
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
  for (const rule of SHAPE_RULES) {
    out = out.replace(rule.pattern, (...args: unknown[]) => {
      count += 1;
      const groups = args.slice(0, -2).map((arg) => (typeof arg === 'string' ? arg : ''));
      const [match = '', ...rest] = groups;
      return rule.replace(match, ...rest);
    });
  }
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
  out = out.replace(KEYED_ADJACENT, (match, dashes: string, key: string, gap: string) => {
    if (!isSecretKey(key) || revealKeys.has(key)) {
      return match;
    }
    count += 1;
    return `${dashes}${key}${gap}${MASK}`;
  });

  if (kept.length > 0) {
    out = out.replace(/\uE000(\d+)\uE001/g, (_m, index: string) => kept[Number(index)] ?? '');
  }
  return { value: out, count };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Walks any shaped payload: every string goes through `scrubText`, and a string sitting under a
 * secret key name (`{"password": "x"}` from a `db query` row) is masked whole. Returns a copy;
 * the input is never mutated.
 */
export function scrub<T>(value: T, options: ScrubOptions = {}): ScrubResult<T> {
  let count = 0;
  const revealKeys = options.revealKeys ?? new Set<string>();
  const walk = (node: unknown, key: string | null): unknown => {
    if (typeof node === 'string') {
      if (
        key !== null &&
        isSecretKey(key) &&
        !revealKeys.has(key) &&
        node.length > 0 &&
        node !== MASK
      ) {
        count += 1;
        return MASK;
      }
      const result = scrubText(node, options);
      count += result.count;
      return result.value;
    }
    if (Array.isArray(node)) {
      return node.map((item) => walk(item, null));
    }
    if (isPlainObject(node)) {
      const copy: Record<string, unknown> = {};
      for (const [childKey, child] of Object.entries(node)) {
        copy[childKey] = walk(child, childKey);
      }
      return copy;
    }
    return node;
  };
  const scrubbed = walk(value, null) as T;
  return { value: scrubbed, count };
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
