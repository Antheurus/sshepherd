import { closeSync, constants, fstatSync, openSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, join } from 'node:path';
import { describeError } from '../errors.ts';
import {
  EXEC_DEF_MAX_TIMEOUT_SEC,
  EXEC_MAX_ARGV_ITEMS,
  EXEC_MAX_DEF_FILE_BYTES,
  EXEC_MAX_DEFS,
  EXEC_MAX_PARAM_BYTES,
  EXEC_MAX_PARAMS,
  EXEC_MAX_PATH_PARAMS,
  EXEC_TIMEOUT_SEC,
} from '../limits.ts';
import { arg, optStrOrNull, reqStr } from '../op-args.ts';
import { capLines, recountLines } from '../parsers/logs-shape.ts';
import { shellJoinExact, shq } from '../quote.ts';
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
 * whose argv runs a shell or another program that executes code it is handed.
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
  timeoutSec: number | null;
  params: ParamDef[];
}

const DEF_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const PARAM_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,31}$/;
const CONTAINER_NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const SLOT = /^\{([A-Za-z_][A-Za-z0-9_]{0,31})\}$/;
const DEF_KEYS = new Set([
  'summary',
  'argv',
  'mutating',
  'container',
  'allow_shell',
  'timeout',
  'params',
]);
const PARAM_KEYS: Record<ParamType['type'], string[]> = {
  enum: ['values'],
  int: ['min', 'max'],
  path: ['under'],
  regex: ['pattern'],
  container: [],
};

/** Shells: argv naming one anywhere, or a value naming one, needs `allow_shell`. `su` runs the
 *  target user's shell, so it is one. */
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
  'su',
]);
/** General-purpose interpreters: each runs text it is handed as code, so they are treated exactly
 *  like a shell. `ssh` runs its command in the remote user's shell; `script -c` and `watch` run
 *  theirs through `sh -c`. */
const INTERPRETERS = new Set([
  'perl',
  'python',
  'pypy',
  'ruby',
  'irb',
  'node',
  'nodejs',
  'deno',
  'bun',
  'lua',
  'tclsh',
  'wish',
  'expect',
  'awk',
  'gawk',
  'mawk',
  'nawk',
  'pwsh',
  'powershell',
  'Rscript',
  'script',
  'watch',
  'ssh',
]);

/** A program's name as the code-runner lists match it: the basename, case-sensitive, with a
 *  version suffix dropped (`/usr/bin/python3.11` is `python`, `php8.2` is `php`). */
function programName(item: string): string {
  return basename(item).replace(/[\d.]+$/, '');
}

function runsCodeByName(item: string): boolean {
  const name = programName(item);
  return SHELLS.has(name) || INTERPRETERS.has(name);
}

/** `--name[=v]` names one of `options`, abbreviations included (GNU tools accept any unambiguous
 *  prefix, so `--use` is `--use-compress-program`). */
function longOptionIn(item: string, options: readonly string[]): boolean {
  if (!item.startsWith('--') || item.length < 4) {
    return false;
  }
  const name = item.slice(2).split('=')[0] ?? '';
  return options.some((option) => option.startsWith(name));
}

/** A short-option cluster (`-xIf`) holding one of `letters`. */
function shortOptionIn(item: string, letters: string): boolean {
  return /^-[A-Za-z]/.test(item) && [...item.slice(1)].some((char) => letters.includes(char));
}

/** A GNU sed script runs a command when it holds the `e` command or an `s///e` flag; with
 *  `fileCommands` a script that reads or writes a file (`r` `R` `w` `W`, `s///w`) counts too. Read
 *  command by command so a `;` inside an `s` expression is not mistaken for a separator. */
function sedScriptRunsCode(script: string, fileCommands = false): boolean {
  let at = 0;
  const skipDelimited = (delimiter: string): void => {
    while (at < script.length && script[at] !== delimiter) {
      at += script[at] === '\\' ? 2 : 1;
    }
    at += 1;
  };
  while (at < script.length) {
    const char = script[at] ?? '';
    if (/[\s;{}!,~$0-9+]/.test(char)) {
      at += 1;
      continue;
    }
    if (char === '#') {
      while (at < script.length && script[at] !== '\n') {
        at += 1;
      }
      continue;
    }
    if (char === '/' || char === '\\') {
      at += char === '\\' ? 2 : 1;
      skipDelimited(char === '\\' ? (script[at - 1] ?? '') : '/');
      continue;
    }
    if (char === 'e' || (fileCommands && 'rRwW'.includes(char))) {
      return true;
    }
    at += 1;
    if (char === 's' || char === 'y') {
      const delimiter = script[at] ?? '';
      at += 1;
      skipDelimited(delimiter);
      skipDelimited(delimiter);
      const flags = /^[A-Za-z0-9]*/.exec(script.slice(at))?.[0] ?? '';
      if (char === 's' && (flags.includes('e') || (fileCommands && flags.includes('w')))) {
        return true;
      }
      at += flags.length;
    } else if ('aicbtT:rRwW'.includes(char)) {
      while (
        at < script.length &&
        script[at] !== '\n' &&
        !(char !== 'a' && char !== 'i' && char !== 'c' && script[at] === ';')
      ) {
        at += 1;
      }
    }
  }
  return false;
}

/** Whether sed, followed by `rest`, runs code: a script that is a param (the caller would write
 *  the sed program), a literal one holding `e`, or a script file that is a param. The scripts are
 *  every `-e`/`--expression` argument, or the first operand when there is none, read both ways
 *  sed parses: GNU getopt moving options past operands, and option parsing stopping at the first
 *  operand (POSIXLY_CORRECT from an `env` prefix or the host's login environment, busybox, BSD). */
function sedRunsCode(rest: readonly string[]): boolean {
  return [false, true].some((stopAtOperand) => sedScriptsRunCode(rest, stopAtOperand));
}

function sedScriptsRunCode(rest: readonly string[], stopAtOperand: boolean): boolean {
  const scripts: string[] = [];
  const files: string[] = [];
  const operands: string[] = [];
  for (let index = 0; index < rest.length; index += 1) {
    const item = rest[index] ?? '';
    if (stopAtOperand && operands.length > 0) {
      operands.push(item);
      continue;
    }
    const short = /^-[A-Za-z]*?([ef])(.*)$/.exec(item);
    const long = item.startsWith('--') ? (item.slice(2).split('=')[0] ?? '') : '';
    const longInto =
      long === ''
        ? null
        : 'expression'.startsWith(long)
          ? scripts
          : 'file'.startsWith(long)
            ? files
            : null;
    if (longInto !== null) {
      const eq = item.indexOf('=');
      longInto.push(eq < 0 ? (rest[index + 1] ?? '') : item.slice(eq + 1));
      index += eq < 0 ? 1 : 0;
    } else if (short !== null && !item.startsWith('--')) {
      const glued = short[2] ?? '';
      const value = glued.length > 0 ? glued : (rest[index + 1] ?? '');
      index += glued.length > 0 ? 0 : 1;
      (short[1] === 'f' ? files : scripts).push(value);
    } else if (item === '-l' || item === '--line-length') {
      index += 1;
    } else if (!item.startsWith('-')) {
      operands.push(item);
    }
  }
  if (scripts.length === 0 && files.length === 0 && operands[0] !== undefined) {
    scripts.push(operands[0]);
  }
  return (
    files.some((file) => SLOT.test(file)) ||
    scripts.some((script) => SLOT.test(script) || sedScriptRunsCode(script))
  );
}

/** The options before a program's first operand (its script, or a git subcommand), skipping the
 *  value of each option in `valueShort`; an option in `stopShort` ends them after its value. */
function leadingOptions(rest: readonly string[], valueShort: string, stopShort = ''): string[] {
  const options: string[] = [];
  for (let index = 0; index < rest.length; index += 1) {
    const item = rest[index] ?? '';
    if (item === '--' || !item.startsWith('-')) {
      break;
    }
    options.push(item);
    const letter = item.length === 2 ? (item[1] ?? '') : '';
    if (letter !== '' && valueShort.includes(letter)) {
      index += 1;
      if (stopShort.includes(letter)) {
        break;
      }
    }
  }
  return options;
}

/** Programs that run code only through certain options: each names, for the items after it,
 *  whether they make it a code runner. */
const RUNS_CODE_WITH: Record<string, (rest: readonly string[]) => boolean> = {
  php: (rest) =>
    leadingOptions(rest, 'cdzfrBRFE', 'f').some(
      (item) =>
        (!item.startsWith('--') && /^-[rBRE]/.test(item)) ||
        longOptionIn(item, ['run', 'process-begin', 'process-code', 'process-end']),
    ),
  find: (rest) =>
    rest.some((item) => ['-exec', '-execdir', '-ok', '-okdir', '-delete'].includes(item)),
  git: (rest) =>
    leadingOptions(rest, 'cC').some(
      (item) => item === '-c' || longOptionIn(item, ['exec-path', 'config-env']),
    ) ||
    rest.some(
      (item) => item.startsWith('core.') || longOptionIn(item, ['upload-pack', 'receive-pack']),
    ),
  tar: (rest) =>
    rest.some(
      (item, index) =>
        longOptionIn(item, [
          'to-command',
          'use-compress-program',
          'checkpoint-action',
          'info-script',
          'new-volume-script',
          'rsh-command',
          'rmt-command',
        ]) ||
        (!item.startsWith('--') && shortOptionIn(item, 'IF')) ||
        (index === 0 && /^[A-Za-z]+$/.test(item) && /[IF]/.test(item)),
    ),
  rsync: (rest) =>
    rest.some(
      (item) =>
        longOptionIn(item, ['rsh', 'rsync-path']) ||
        (!item.startsWith('--') && shortOptionIn(item, 'e')),
    ),
  scp: (rest) => rest.some((item) => !item.startsWith('--') && shortOptionIn(item, 'SoF')),
  sed: sedRunsCode,
  env: (rest) => rest.some((item) => item === '-S' || longOptionIn(item, ['split-string'])),
};

/** Programs that start another program: per wrapper, its options that take a value and those
 *  that make it start a shell (short letters, long names), and how many operands come before the
 *  program it runs. */
interface Wrapper {
  valueShort: string;
  valueLong: string[];
  shellShort?: string;
  shellLong?: string[];
  operands: number;
  assignments?: true;
  /** Run with no program, it starts a shell (`chroot /jail`). */
  bareIsShell?: true;
}
const WRAPPERS: Record<string, Wrapper> = {
  env: {
    valueShort: 'auCSP',
    valueLong: ['argv0', 'unset', 'chdir', 'split-string'],
    operands: 0,
    assignments: true,
  },
  nice: { valueShort: 'n', valueLong: ['adjustment'], operands: 0 },
  timeout: { valueShort: 'ks', valueLong: ['kill-after', 'signal'], operands: 1 },
  stdbuf: {
    valueShort: 'ioe',
    valueLong: ['input', 'output', 'error'],
    operands: 0,
  },
  nohup: { valueShort: '', valueLong: [], operands: 0 },
  xargs: {
    valueShort: 'adEILnPs',
    valueLong: ['arg-file', 'delimiter', 'max-args', 'max-procs', 'max-chars', 'process-slot-var'],
    operands: 0,
  },
  setsid: { valueShort: '', valueLong: [], operands: 0 },
  sudo: {
    valueShort: 'ughpCDrtTUR',
    valueLong: [
      'user',
      'group',
      'host',
      'prompt',
      'close-from',
      'chdir',
      'role',
      'type',
      'command-timeout',
      'other-user',
      'chroot',
    ],
    shellShort: 'si',
    shellLong: ['shell', 'login'],
    operands: 0,
    assignments: true,
  },
  doas: { valueShort: 'uC', valueLong: [], shellShort: 's', operands: 0 },
  chroot: {
    valueShort: '',
    valueLong: ['userspec', 'groups'],
    operands: 1,
    bareIsShell: true,
  },
};

/** The program `argv`'s wrappers start and its index (`argv.length` when they start none), or
 *  why the chain runs code: the program is a param (the caller would pick it), or a wrapper
 *  starts a shell. */
function wrappedProgram(argv: readonly string[]): { at: number; problem: string | null } {
  let at = 0;
  for (;;) {
    const program = programName(argv[at] ?? '');
    const wrapper = Object.hasOwn(WRAPPERS, program) ? WRAPPERS[program] : undefined;
    if (wrapper === undefined) {
      return { at, problem: SLOT.test(argv[at] ?? '') ? 'the program it runs is a param' : null };
    }
    const name = program;
    at += 1;
    let operands = wrapper.operands;
    while (at < argv.length) {
      const item = argv[at] ?? '';
      if (item === '--') {
        at += 1;
        break;
      }
      if (item.startsWith('--')) {
        if (longOptionIn(item, wrapper.shellLong ?? [])) {
          return { at, problem: `${name} ${item} starts a shell` };
        }
        at += longOptionIn(item, wrapper.valueLong) && !item.includes('=') ? 2 : 1;
        continue;
      }
      if (/^-./.test(item)) {
        let step = 1;
        for (const [index, letter] of [...item.slice(1)].entries()) {
          if ((wrapper.shellShort ?? '').includes(letter)) {
            return { at, problem: `${name} -${letter} starts a shell` };
          }
          if (wrapper.valueShort.includes(letter)) {
            step = index === item.length - 2 ? 2 : 1;
            break;
          }
        }
        at += step;
        continue;
      }
      if (wrapper.assignments === true && /^[A-Za-z_][A-Za-z0-9_]*=/.test(item)) {
        at += 1;
        continue;
      }
      if (operands > 0) {
        operands -= 1;
        at += 1;
        continue;
      }
      break;
    }
    if (at >= argv.length) {
      return {
        at,
        problem: wrapper.bareIsShell === true ? `${name} with no program starts a shell` : null,
      };
    }
  }
}

/** How a data-only program reads one of its options: `flag` takes no value, `value` takes the
 *  next item or a glued one, `optional` only a glued one (`sed -i.bak`, `tail --follow=name`), and
 *  `code` a value the program runs or reads as a script, which a param may never fill. */
type OptionKind = 'flag' | 'value' | 'optional' | 'code';

interface OptionTable {
  short: Record<string, OptionKind>;
  long: Record<string, OptionKind>;
}

/** One table from its spellings: short letters per kind, long names (without `--`) per kind,
 *  space-separated. Only these exact spellings pass: no GNU abbreviation, no unknown option. */
function options(spec: {
  flags?: string;
  values?: string;
  optional?: string;
  code?: string;
  long?: string;
  longValues?: string;
  longOptional?: string;
  longCode?: string;
}): OptionTable {
  const short: Record<string, OptionKind> = {};
  const long: Record<string, OptionKind> = {};
  const shortKinds: [string | undefined, OptionKind][] = [
    [spec.flags, 'flag'],
    [spec.values, 'value'],
    [spec.optional, 'optional'],
    [spec.code, 'code'],
  ];
  for (const [letters, kind] of shortKinds) {
    for (const letter of letters ?? '') {
      short[letter] = kind;
    }
  }
  const longKinds: [string | undefined, OptionKind][] = [
    [spec.long, 'flag'],
    [spec.longValues, 'value'],
    [spec.longOptional, 'optional'],
    [spec.longCode, 'code'],
  ];
  for (const [names, kind] of longKinds) {
    for (const name of (names ?? '').split(' ').filter((word) => word.length > 0)) {
      long[name] = kind;
    }
  }
  return { short, long };
}

const GREP_OPTIONS = options({
  flags: 'EFGPiywxzsvcLloqbHhnTZUarR',
  values: 'efmABCdD',
  long: 'extended-regexp fixed-strings basic-regexp perl-regexp ignore-case no-ignore-case word-regexp line-regexp null-data no-messages invert-match count files-without-match files-with-matches only-matching quiet silent byte-offset with-filename no-filename line-number line-buffered initial-tab null binary text recursive dereference-recursive',
  longValues:
    'regexp file max-count after-context before-context context label binary-files devices directories exclude exclude-from exclude-dir include',
  longOptional: 'color colour',
});
const SUM_OPTIONS = options({
  flags: 'bctwz',
  long: 'binary check tag text zero ignore-missing quiet status strict warn',
});
const DOCKER_STOP_OPTIONS = options({ values: 'st', longValues: 'signal time' });
const NO_OPTIONS = options({});
const SYSTEMCTL_OPTIONS = options({
  flags: 'aql',
  values: 'noptP',
  long: 'all quiet full no-pager no-legend plain value now no-block no-ask-password system user failed show-types',
  longValues: 'lines output property type state job-mode',
});

/** The data-only programs (rule A7): a param may appear in argv only when argv[0] is one of these,
 *  each a program that reads its arguments as data and never starts a program one of them names.
 *  `date` and `hostname` are not here: given one operand, each tries to set the clock or the host
 *  name. Every literal option is checked against the program's table by exact spelling. No option
 *  may follow the first operand (`paramProblem`). `subcommands`: the first item after the
 *  program is one of these, written literally, and the options after it are that subcommand's.
 *  `find`, `sed` and `php` are read by their own rules in `paramProblem`. `git` is not here: its
 *  aliases, `-c`, pager and textconv settings, and a repository's own config can run a program. */
const DATA_PROGRAMS: Record<
  string,
  { options: OptionTable; subcommands?: Record<string, OptionTable> }
> = {
  cat: {
    options: options({
      flags: 'AbeEnstTuv',
      long: 'show-all number-nonblank show-ends number squeeze-blank show-tabs show-nonprinting',
    }),
  },
  tac: {
    options: options({ flags: 'br', values: 's', long: 'before regex', longValues: 'separator' }),
  },
  head: {
    options: options({
      flags: 'qvz',
      values: 'cn',
      long: 'quiet silent verbose zero-terminated',
      longValues: 'bytes lines',
    }),
  },
  tail: {
    options: options({
      flags: 'fFqvz',
      values: 'cns',
      long: 'retry quiet silent verbose zero-terminated',
      longValues: 'bytes lines max-unchanged-stats pid sleep-interval',
      longOptional: 'follow',
    }),
  },
  ls: {
    options: options({
      flags: 'aAbBcCdDfFgGhHiklLmnNopqQrRsStuUvxXZ1',
      values: 'ITw',
      long: 'all almost-all author escape ignore-backups directory dired file-type full-time group-directories-first no-group human-readable si dereference-command-line dereference-command-line-symlink-to-dir dereference hide-control-chars show-control-chars inode kibibytes literal numeric-uid-gid quote-name recursive reverse size zero context',
      longValues:
        'block-size format hide ignore indicator-style quoting-style sort time time-style tabsize width',
      longOptional: 'classify color hyperlink',
    }),
  },
  du: {
    options: options({
      flags: '0abcDHhklLmPSsx',
      values: 'BdtX',
      long: 'null all apparent-size bytes total dereference-args human-readable inodes count-links dereference no-dereference separate-dirs si summarize one-file-system',
      longValues: 'block-size max-depth files0-from threshold time-style exclude-from exclude',
      longOptional: 'time',
    }),
  },
  df: {
    options: options({
      flags: 'ahHiklPT',
      values: 'Btx',
      long: 'all human-readable si inodes local no-sync portability sync total print-type',
      longValues: 'block-size type exclude-type',
      longOptional: 'output',
    }),
  },
  stat: {
    options: options({
      flags: 'Lft',
      values: 'c',
      long: 'dereference file-system terse',
      longValues: 'format printf cached',
    }),
  },
  wc: {
    options: options({
      flags: 'cmlLw',
      long: 'bytes chars lines max-line-length words',
      longValues: 'files0-from total',
    }),
  },
  grep: { options: GREP_OPTIONS },
  egrep: { options: GREP_OPTIONS },
  fgrep: { options: GREP_OPTIONS },
  zcat: { options: options({ flags: 'flqtv', long: 'force list quiet test verbose' }) },
  md5sum: { options: SUM_OPTIONS },
  sha1sum: { options: SUM_OPTIONS },
  sha256sum: { options: SUM_OPTIONS },
  readlink: {
    options: options({
      flags: 'femnqsvz',
      long: 'canonicalize canonicalize-existing canonicalize-missing no-newline quiet silent verbose zero',
    }),
  },
  realpath: {
    options: options({
      flags: 'eLmPqsz',
      long: 'canonicalize-existing canonicalize-missing logical physical quiet strip no-symlinks zero',
      longValues: 'relative-to relative-base',
    }),
  },
  echo: { options: options({ flags: 'neE' }) },
  id: { options: options({ flags: 'aZgGnruz', long: 'context group groups name real user zero' }) },
  uname: {
    options: options({
      flags: 'asnrvmpio',
      long: 'all kernel-name nodename kernel-release kernel-version machine processor hardware-platform operating-system',
    }),
  },
  uptime: { options: options({ flags: 'ps', long: 'pretty since' }) },
  free: {
    options: options({
      flags: 'bkmghlwtv',
      values: 'cs',
      long: 'bytes kibi mebi gibi tebi pebi kilo mega giga tera peta human lohi wide total committed si',
      longValues: 'count seconds',
    }),
  },
  ps: {
    options: options({
      flags: 'AadeNTrfFljHwMyLcxZ',
      values: 'CGgpqstuUoOk',
      long: 'deselect forest headers no-headers cumulative',
      longValues:
        'pid ppid sid tty user User group Group format sort cols columns lines width rows',
    }),
  },
  touch: {
    options: options({
      flags: 'acfhm',
      values: 'dtr',
      long: 'no-create no-dereference',
      longValues: 'date reference time',
    }),
  },
  mkdir: {
    options: options({
      flags: 'pvZ',
      values: 'm',
      long: 'parents verbose',
      longValues: 'mode',
      longOptional: 'context',
    }),
  },
  rmdir: { options: options({ flags: 'pv', long: 'ignore-fail-on-non-empty parents verbose' }) },
  rm: {
    options: options({
      flags: 'fiIrRdv',
      long: 'force recursive dir verbose one-file-system no-preserve-root preserve-root',
      longOptional: 'interactive',
    }),
  },
  cp: {
    options: options({
      flags: 'aAbdfiHlLnPprRsTuvxZ',
      values: 'St',
      long: 'archive attributes-only copy-contents debug force interactive link dereference no-clobber no-dereference parents recursive remove-destination strip-trailing-slashes symbolic-link no-target-directory keep-directory-symlink verbose one-file-system',
      longValues: 'suffix target-directory sparse no-preserve',
      longOptional: 'backup preserve reflink update context',
    }),
  },
  mv: {
    options: options({
      flags: 'bfinTuvZ',
      values: 'St',
      long: 'force interactive no-clobber no-copy strip-trailing-slashes no-target-directory verbose exchange debug',
      longValues: 'suffix target-directory',
      longOptional: 'backup update context',
    }),
  },
  ln: {
    options: options({
      flags: 'bdFfinLPrsTv',
      values: 'St',
      long: 'directory force interactive logical no-dereference physical relative symbolic no-target-directory verbose',
      longValues: 'suffix target-directory',
      longOptional: 'backup',
    }),
  },
  chmod: {
    options: options({
      flags: 'cfvR',
      long: 'changes silent quiet verbose no-preserve-root preserve-root recursive',
      longValues: 'reference',
    }),
  },
  chown: {
    options: options({
      flags: 'cfvhRHLP',
      long: 'changes silent quiet verbose dereference no-dereference no-preserve-root preserve-root recursive',
      longValues: 'from reference',
    }),
  },
  journalctl: {
    options: options({
      flags: 'aefklmqrxN',
      values: 'cDFgnopSUtTu',
      optional: 'b',
      long: 'all pager-end follow dmesg full merge no-full no-pager no-tail quiet reverse catalog utc system user list-boots show-cursor no-hostname header disk-usage',
      longValues:
        'cursor after-cursor cursor-file directory field file grep output output-fields priority since until identifier exclude-identifier unit user-unit facility root namespace',
      longOptional: 'boot lines case-sensitive',
    }),
  },
  sed: {
    options: options({
      flags: 'nErsuzb',
      values: 'l',
      optional: 'i',
      code: 'ef',
      long: 'quiet silent debug posix regexp-extended separate sandbox unbuffered null-data follow-symlinks binary',
      longValues: 'line-length',
      longOptional: 'in-place',
      longCode: 'expression file',
    }),
  },
  find: { options: NO_OPTIONS },
  php: { options: NO_OPTIONS },
  docker: {
    options: NO_OPTIONS,
    subcommands: {
      logs: options({
        flags: 'ft',
        values: 'n',
        long: 'details follow timestamps',
        longValues: 'since tail until',
      }),
      inspect: options({ flags: 's', values: 'f', long: 'size', longValues: 'format type' }),
      ps: options({
        flags: 'alqs',
        values: 'fn',
        long: 'all latest no-trunc quiet size',
        longValues: 'filter format last',
      }),
      stats: options({ flags: 'a', long: 'all no-stream no-trunc', longValues: 'format' }),
      top: NO_OPTIONS,
      port: NO_OPTIONS,
      diff: NO_OPTIONS,
      history: options({ flags: 'Hq', long: 'human no-trunc quiet', longValues: 'format' }),
      images: options({
        flags: 'aq',
        values: 'f',
        long: 'all digests no-trunc quiet',
        longValues: 'filter format',
      }),
      restart: DOCKER_STOP_OPTIONS,
      start: options({ flags: 'ai', long: 'attach interactive', longValues: 'detach-keys' }),
      stop: DOCKER_STOP_OPTIONS,
      kill: options({ values: 's', longValues: 'signal' }),
      pause: NO_OPTIONS,
      unpause: NO_OPTIONS,
      wait: NO_OPTIONS,
    },
  },
  systemctl: {
    options: NO_OPTIONS,
    subcommands: Object.fromEntries(
      [
        'status',
        'show',
        'cat',
        'is-active',
        'is-enabled',
        'is-failed',
        'list-units',
        'list-timers',
        'start',
        'stop',
        'restart',
        'try-restart',
        'reload',
        'reload-or-restart',
      ].map((verb) => [verb, SYSTEMCTL_OPTIONS]),
    ),
  },
};

/** find's own words, by exact spelling: the leading options, then the tests and actions of its
 *  expression that take a value (which a param may fill) or none. Everything else, `-exec`,
 *  `-execdir`, `-ok`, `-okdir`, `-delete`, `-fprint`, `-fprint0`, `-fprintf` and `-fls` among it,
 *  is refused in a definition with a param. */
const FIND_LEADING = new Set(['-H', '-L', '-P', '-O0', '-O1', '-O2', '-O3']);
const FIND_VALUE_WORDS = new Set([
  '-name',
  '-iname',
  '-path',
  '-ipath',
  '-wholename',
  '-iwholename',
  '-regex',
  '-iregex',
  '-regextype',
  '-lname',
  '-ilname',
  '-type',
  '-xtype',
  '-size',
  '-perm',
  '-user',
  '-group',
  '-uid',
  '-gid',
  '-links',
  '-inum',
  '-samefile',
  '-newer',
  '-anewer',
  '-cnewer',
  '-atime',
  '-amin',
  '-ctime',
  '-cmin',
  '-mtime',
  '-mmin',
  '-used',
  '-fstype',
  '-maxdepth',
  '-mindepth',
  '-printf',
  '-files0-from',
  ...['a', 'B', 'c', 'm'].flatMap((x) => ['a', 'B', 'c', 'm', 't'].map((y) => `-newer${x}${y}`)),
]);
const FIND_FLAG_WORDS = new Set([
  '-print',
  '-print0',
  '-ls',
  '-prune',
  '-quit',
  '-true',
  '-false',
  '-empty',
  '-readable',
  '-writable',
  '-executable',
  '-nouser',
  '-nogroup',
  '-xdev',
  '-mount',
  '-depth',
  '-daystart',
  '-follow',
  '-noleaf',
  '-ignore_readdir_race',
  '-noignore_readdir_race',
  '-not',
  '-and',
  '-or',
  '-a',
  '-o',
  '(',
  ')',
  '!',
  ',',
]);

/** How getopt splits a program's items: `permute` is GNU's default, reading options anywhere;
 *  `stop` ends option parsing at the first operand, as GNU does under POSIXLY_CORRECT and busybox
 *  and BSD always do. */
export type ParseMode = 'permute' | 'stop';

export interface DataArgv {
  problem: string | null;
  operands: string[];
  code: string[];
}

/** Reads `items` the way getopt would with `table` in `mode`: every option checked by exact
 *  spelling, the value of each value-taking one consumed. Returns the operands and each `code`
 *  option's value, or why the items are refused (an unknown or abbreviated option, a param filling
 *  a `code` option). */
function readOptions(
  program: string,
  items: readonly string[],
  table: OptionTable,
  mode: ParseMode,
): DataArgv {
  const operands: string[] = [];
  const code: string[] = [];
  const refuse = (problem: string) => ({ problem, operands, code });
  let ended = false;
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index] ?? '';
    if (mode === 'stop' && operands.length > 0) {
      ended = true;
    }
    if (ended || item === '-' || !item.startsWith('-')) {
      operands.push(item);
      continue;
    }
    if (item === '--') {
      ended = true;
      continue;
    }
    let spelled = item;
    let kind: OptionKind | undefined;
    let value: string | undefined;
    if (item.startsWith('--')) {
      const eq = item.indexOf('=');
      spelled = eq < 0 ? item : item.slice(0, eq);
      const name = spelled.slice(2);
      kind = Object.hasOwn(table.long, name) ? table.long[name] : undefined;
      if (kind === undefined) {
        return refuse(
          `${program} ${spelled} is not an option sshepherd knows by that exact spelling`,
        );
      }
      if (eq >= 0) {
        if (kind === 'flag') {
          return refuse(`${program} ${spelled} takes no value`);
        }
        value = item.slice(eq + 1);
      } else if (kind === 'value' || kind === 'code') {
        value = items[index + 1];
        index += 1;
      }
    } else {
      for (let at = 1; at < item.length; at += 1) {
        const letter = item[at] ?? '';
        spelled = `-${letter}`;
        kind = Object.hasOwn(table.short, letter) ? table.short[letter] : undefined;
        if (kind === undefined) {
          return refuse(`${program} ${spelled} is not an option sshepherd knows for ${program}`);
        }
        if (kind === 'flag') {
          continue;
        }
        const glued = item.slice(at + 1);
        if (glued.length > 0 || kind === 'optional') {
          value = glued;
        } else {
          value = items[index + 1];
          index += 1;
        }
        break;
      }
    }
    if (kind === 'code') {
      if (value === undefined || SLOT.test(value)) {
        return refuse(`${program} ${spelled} reads code, and its value is a param or missing`);
      }
      code.push(spelled === '-f' || spelled === '--file' ? '' : value);
    }
  }
  return { problem: null, operands, code };
}

/** find: leading options, start points (a param may be one), then an expression whose every word
 *  is a known test or action, a param filling only the value of a test that takes one. */
function findProblem(rest: readonly string[]): string | null {
  let index = 0;
  while (index < rest.length && FIND_LEADING.has(rest[index] ?? '')) {
    index += 1;
  }
  while (index < rest.length && !/^[-(!]/.test(rest[index] ?? '')) {
    index += 1;
  }
  for (; index < rest.length; index += 1) {
    const item = rest[index] ?? '';
    if (FIND_VALUE_WORDS.has(item)) {
      index += 1;
      continue;
    }
    if (FIND_FLAG_WORDS.has(item)) {
      continue;
    }
    return SLOT.test(item)
      ? `puts ${item} in find's expression, where only a start point or a test's value may be a param`
      : `uses find ${item}, which is not a find test sshepherd knows to read data only`;
  }
  return null;
}

/** How the getopt-parsed data-only program at argv[0] reads the rest of argv in `mode` (a
 *  subcommand's items by that subcommand's table), or why argv[0] or its subcommand is not one.
 *  `find` and `php` parse by their own grammar and are read in `paramProblem` instead. */
export function readDataArgv(argv: readonly string[], mode: ParseMode): DataArgv {
  const program = programName(argv[0] ?? '');
  const known = Object.hasOwn(DATA_PROGRAMS, program) ? DATA_PROGRAMS[program] : undefined;
  if (known === undefined) {
    return {
      problem: `hands a param to ${program}, which is not a program sshepherd knows to take its arguments only as data (a param may follow only a data-only program as argv[0], with no wrapper such as env before it)`,
      operands: [],
      code: [],
    };
  }
  const rest = argv.slice(1);
  if (known.subcommands === undefined) {
    return readOptions(program, rest, known.options, mode);
  }
  const sub = rest[0] ?? '';
  const subTable = Object.hasOwn(known.subcommands, sub) ? known.subcommands[sub] : undefined;
  if (subTable === undefined || SLOT.test(sub)) {
    return {
      problem: `hands a param to ${program} ${sub}, which is not one of its data-only subcommands (written right after ${program})`,
      operands: [],
      code: [],
    };
  }
  return readOptions(program, rest.slice(1), subTable, mode);
}

/** Why a param in `argv` could become code, or `null` (rule A7). A param may appear only when
 *  argv[0] is on DATA_PROGRAMS, with no wrapper before it: anything else (`env`, `nice`, `sudo`,
 *  `timeout`, `xargs`, `ionice`, `flock`, `docker exec`, a site's own script) may start a program
 *  one of its arguments names or change how the next program parses (`env POSIXLY_CORRECT=1`),
 *  and no list of such programs is ever complete. No option may follow the first operand, so the
 *  split comes out the same whether the program permutes options or stops at the first operand. */
function paramProblem(argv: readonly string[]): string | null {
  const program = programName(argv[0] ?? '');
  const rest = argv.slice(1);
  if (program === 'find') {
    return findProblem(rest);
  }
  if (program === 'php') {
    const script = rest[0] ?? '';
    return script === '' || SLOT.test(script) || script.startsWith('-')
      ? 'hands a param to php without a literal script as its first item (php reads its options before the script and runs the script it is handed)'
      : null;
  }
  const read = readDataArgv(argv, 'permute');
  if (read.problem !== null) {
    return read.problem;
  }
  const stopped = readDataArgv(argv, 'stop');
  const moved = stopped.operands.find((item, index) => item !== read.operands[index]);
  if (moved !== undefined) {
    return `puts ${moved} after the first operand ${read.operands[0] ?? ''}: GNU getopt reads it as an option there, but under POSIXLY_CORRECT (an env prefix or the host's login environment) and in busybox and BSD tools option parsing stops at the first operand, so it would be an operand and the param's role could change (write every option before the first operand)`;
  }
  if (program === 'sed') {
    const scripts = read.code.length > 0 ? read.code : read.operands.slice(0, 1);
    if (read.code.length === 0 && SLOT.test(scripts[0] ?? '')) {
      return 'hands sed a param as its script (the first operand, with no -e or -f)';
    }
    if (scripts.some((script) => sedScriptRunsCode(script, true))) {
      return 'runs a sed script that executes a command or reads or writes a file (e, r, R, w, W, s///e, s///w)';
    }
  }
  return null;
}

/** Why the def's argv runs code it is handed (a shell, an interpreter, a code-running option, a
 *  wrapper around one, a param a program could run), or `null`. Every literal element is checked,
 *  not only argv[0], so an interpreter behind a wrapper this list does not know (`docker exec app
 *  perl`) is still found. A def with a param is then held to rule A7 (`paramProblem`); one with
 *  none to the wrapper walk. */
function codeRunner(argv: readonly string[]): string | null {
  for (const [index, item] of argv.entries()) {
    if (SLOT.test(item)) {
      continue;
    }
    if (runsCodeByName(item)) {
      return `runs ${programName(item)}`;
    }
    const program = programName(item);
    const check = Object.hasOwn(RUNS_CODE_WITH, program) ? RUNS_CODE_WITH[program] : undefined;
    if (check?.(argv.slice(index + 1)) === true) {
      return `runs ${programName(item)} with an option that executes code`;
    }
  }
  if (argv.some((item) => SLOT.test(item))) {
    return paramProblem(argv);
  }
  return wrappedProgram(argv).problem;
}

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
      new RegExp(source, 'u');
    } catch {
      throw defError(
        alias,
        `${where}.pattern is not a valid regular expression on its own (every ( and [ closed)`,
      );
    }
    return { type, pattern: new RegExp(`^(?:${source})$`, 'u'), source };
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
  const timeout = raw.timeout;
  if (
    timeout !== undefined &&
    (typeof timeout !== 'number' ||
      !Number.isInteger(timeout) ||
      timeout < 1 ||
      timeout > EXEC_DEF_MAX_TIMEOUT_SEC)
  ) {
    throw defError(
      alias,
      `[${name}].timeout must be a whole number of seconds from 1 to ${EXEC_DEF_MAX_TIMEOUT_SEC}`,
    );
  }
  const params = readParams(alias, name, raw.params);
  const pathCount = params.filter((param) => param.spec.type === 'path').length;
  if (pathCount > EXEC_MAX_PATH_PARAMS) {
    throw defError(
      alias,
      `[${name}] declares ${pathCount} path params; the limit is ${EXEC_MAX_PATH_PARAMS}`,
    );
  }
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
    timeoutSec: typeof timeout === 'number' ? timeout : null,
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
  if (!def.allowShell && runsCodeByName(value)) {
    throw badValue(
      name,
      `the value names a shell or interpreter (${basename(value)})`,
      'Only a definition with allow_shell = true may be handed a shell or interpreter.',
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
    const problem = codeRunner(def.argv);
    if (problem !== null) {
      throw new OpError(
        'VALIDATION_ERROR',
        `'${def.name}' ${problem}; that can execute code, so it needs allow_shell = true`,
        {
          hint: `A human either declares the program itself as argv[0] (container = "<name>" runs it inside a container), or sets allow_shell = true on [${def.name}] in ${fileLabel(alias)} after reading what it runs; references/exec.md lists every program this covers and the data-only programs a param may follow.`,
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
 *  each slot its validated value as one quoted word. With a `path` slot the whole thing is ONE
 *  `sh -c` where the command runs (inside the container too): it resolves the path and checks the
 *  result lies under the resolved root. Where `/proc/self/fd` exists (Linux) it then opens the
 *  resolved directory (or the file's directory) on descriptor 3+N, checks what it actually opened
 *  is still under the root, and hands the command `/proc/self/fd/<n>/<name>`: a directory swapped
 *  for a link after the check cannot redirect the command, because the command reaches the one
 *  already opened. Elsewhere the command gets the resolved path itself. Every value and root is
 *  absolute (checked locally), so `realpath` needs no `--`, which busybox would read as a path. */
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
  const fail = (marker: string, param: ParamDef): string =>
    `{ echo ${marker} ${shq(param.name)} >&2; exit ${GUARD_EXIT}; }`;
  const lines: string[] = [];
  pathParams.forEach((param, index) => {
    const under = param.spec.type === 'path' ? param.spec.under : '';
    lines.push(`u${index}=$(realpath ${shq(under)}) || ${fail(PATH_MISSING, param)}`);
  });
  pathParams.forEach((param, index) => {
    const value = shq(values.get(param.name) ?? '');
    lines.push(
      `test -e ${value} || ${fail(PATH_MISSING, param)}`,
      `r${index}=$(realpath ${value}) || ${fail(PATH_MISSING, param)}`,
      `case "$r${index}" in "$u${index}"|"$u${index}"/*) ;; *) ${fail(PATH_ESCAPE, param)} ;; esac`,
      `a${index}=$r${index}`,
      'if [ -d /proc/self/fd ]; then',
      `  if [ -d "$r${index}" ]; then d${index}=$r${index}; l${index}=.; else d${index}=\${r${index}%/*}; l${index}=\${r${index}##*/}; fi`,
      `  command exec ${3 + index}<"$d${index}" || ${fail(PATH_MISSING, param)}`,
      `  case "$(readlink /proc/self/fd/${3 + index})" in "$u${index}"|"$u${index}"/*) ;; *) ${fail(PATH_ESCAPE, param)} ;; esac`,
      `  a${index}=/proc/self/fd/${3 + index}/$l${index}`,
      'fi',
    );
  });
  const words = def.argv.map((item) => {
    const slot = SLOT.exec(item)?.[1];
    if (slot === undefined) {
      return shq(item);
    }
    const index = pathParams.findIndex((param) => param.name === slot);
    return index < 0 ? shq(values.get(slot) ?? '') : `"$a${index}"`;
  });
  lines.push(`exec ${words.join(' ')}`);
  return shellJoinExact([...prefix, 'sh', '-c', lines.join('\n')]);
}

/** The call's default budget: the definition's own `timeout`, else the op's. A def that cannot be
 *  read here was already refused by `buildRemote`, which runs first. */
function execTimeoutSec(ctx: OpContext): number {
  try {
    return findDef(ctx.alias, reqStr(ctx, 'name')).timeoutSec ?? EXEC_TIMEOUT_SEC;
  } catch {
    return EXEC_TIMEOUT_SEC;
  }
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
  timeoutSecFor: execTimeoutSec,
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
  timeoutSecFor: execTimeoutSec,
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
  timeout_sec: number | null;
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
      timeout_sec: def.timeoutSec,
      argv: def.argv,
      params: def.params.map(describeParam),
    })),
  }),
  shape: (parsed) => parsed as { defs: ExecListEntry[] },
};

export const execOps: OpSpec[] = [execRun as OpSpec, execChange as OpSpec, execList as OpSpec];
