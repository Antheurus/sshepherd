# Named exec

`exec` runs a command sshepherd has no op for, and only one that a human declared in advance for
that alias. There is no free-text form and no `--script`: the agent names a definition and passes
typed values; it never writes the command line.

```bash
sshepherd exec list web-01
sshepherd exec web-01 app-artisan --param cmd=migrate:status        # = exec run (mutating = false)
sshepherd exec web-01 restart-worker --param c=worker --yes         # = exec change (mutating = true)
```

| Op | Takes | Profile | `--yes` | Audited |
|---|---|---|---|---|
| `exec run <alias> <name>` | definitions with `mutating = false`; refuses a mutating one | `read` | no | yes (it returns content) |
| `exec change <alias> <name>` | any definition | `deploy` | yes | yes, refusals included |
| `exec list <alias>` | — | `read` | no | no |

`exec <alias> <name>` reads the definition and picks `run` or `change` from its `mutating`. `exec run`
reads it again and refuses a mutating definition, so a file edited between the two reads can only
fail closed.

Each audit row of `exec run` and `exec change` names the definition (`exec_def`), as a `deploy`
row names its recipe; param values appear only in the args hash.

A read-only definition runs at the `read` profile on purpose: the human who wrote `mutating = false`
in a 0600 file is the one vouching that it only reads, and a `read` session is exactly what named exec
is meant to replace raw `docker exec` reads for.

## The definition file

`~/.config/sshepherd/exec/<alias>.toml` (`SSHEPHERD_EXEC_DIR` overrides the directory). It is refused
unless it is a regular file (not a symbolic link), owned by the user running sshepherd, and has no
group or other permission bits (`chmod 600`). It is read and checked whole on every call: one
malformed definition stops every definition of that alias.

```toml
[app-artisan]
summary = "Read-only artisan commands in the app container"
argv = ["php", "artisan", "{cmd}"]
mutating = false
container = "myapp"                 # optional: runs as docker exec myapp <argv>

[app-artisan.params.cmd]
type = "enum"
values = ["migrate:status", "route:list", "about"]

[show-config]
argv = ["cat", "{file}"]
mutating = false

[show-config.params.file]
type = "path"
under = "/opt/myapp/config"

[restart-worker]
argv = ["docker", "restart", "{c}"]
mutating = true

[restart-worker.params.c]
type = "container"
```

| Field | Required | Meaning |
|---|---|---|
| `argv` | yes | the command as an argv array, 1-64 elements; never one shell string. `argv[0]` is a literal program |
| `mutating` | yes | `true` sends it through `exec change` (`--yes`, profile `deploy`) |
| `summary` | no | shown by `exec list` |
| `container` | no | run inside this container; it must be in the alias's `containers = [...]` in `targets.toml` |
| `allow_shell` | no | `true` lets argv run a shell or interpreter (the list under [Code runners](#code-runners-need-allow_shell)), or take a param where [rule A7](#a-param-follows-only-a-data-only-program-rule-a7) refuses one (a wrapper or unlisted program as argv[0], an option not spelled exactly); off by default |
| `timeout` | no | this definition's budget in seconds, 1-1800 (default 120); `--timeout <sec>` on the call still overrides it, up to 3600 |
| `params.<name>` | no | at most 16, at most 7 of them `path`; each one must be used in argv |

A param fills one whole argv element, written exactly `"{name}"`. `"--file={name}"` is a definition
error: splicing a value into a larger string is how one value becomes two meanings.

### Param types

| `type` | Fields | A value passes when |
|---|---|---|
| `enum` | `values = [...]` | it is one of the values |
| `int` | `min`, `max` (whole numbers, 0 <= min <= max) | it is a whole number in range |
| `path` | `under = "/abs/dir"` | it is absolute, has no `.`/`..` segment, lies under `under`, AND its `realpath` on the host (inside the container when the definition names one) still lies under `realpath(under)` |
| `regex` | `pattern = '...'` | it matches the whole pattern. The pattern must compile on its own (every `(` and `[` closed), so a top-level `\|` can never escape the whole-value anchor |
| `container` | — | it is in the alias's declared `containers` |

`default` (any type) is used when the call omits the param, and is checked like a passed value when
the file is read. A param without a default is required.

## Code runners need `allow_shell`

The human writes the definition, so this list is defence in depth: it stops a value the agent
passes from becoming code in a program that would run it. A definition is refused
(`VALIDATION_ERROR`, no ssh call) unless it has `allow_shell = true` when its argv runs code.
Names match by basename, case-sensitive, with a version suffix dropped (`/usr/bin/python3.11` is
`python`, `php8.2` is `php`), at any position in argv, so `docker exec app perl -e ...` is caught
as well as `perl -e ...`.

| Refused | Programs |
|---|---|
| always | shells: `sh` `bash` `dash` `zsh` `ksh` `mksh` `ash` `yash` `fish` `csh` `tcsh` `busybox` (any applet, `busybox awk` included) `su` |
| always | interpreters: `perl` `python` (`python2`, `python3`, `python3.x`) `pypy` (`pypy3`) `ruby` `irb` `node` `nodejs` `deno` `bun` `lua` `tclsh` `wish` `expect` `awk` `gawk` `mawk` `nawk` `pwsh` `powershell` `Rscript`; `script` and `watch` (each runs its command through `sh -c`); and `ssh` (its command runs in the remote shell) |
| with a code option | `php -r`/`-B`/`-R`/`-E` (and `--run`, `--process-begin`, `--process-code`, `--process-end`) before the script; `php artisan ...` runs |
| | `find` with `-exec`, `-execdir`, `-ok`, `-okdir` or `-delete` |
| | `git` with `-c` or `--exec-path`/`--config-env` before the subcommand, `--upload-pack`/`--receive-pack`, or any `core.*` argument |
| | `tar` with `--to-command`, `--use-compress-program`, `--checkpoint-action`, `--info-script`, `--new-volume-script`, `--rsh-command`, `--rmt-command` (any unambiguous abbreviation), or `I`/`F` in a short-option cluster (`-I`, `-xIf`, old-style `xIf`) |
| | `rsync` with `-e`/`--rsh` or `--rsync-path`; `scp` with `-S`, `-o` or `-F` |
| | GNU `sed` whose script holds the `e` command or an `s///e` flag, or whose script (or `-f` file) is a param; `--expression`/`--file` are matched in any abbreviation (`--expr`, `--e`, `--fi`) |
| | `env -S`/`--split-string` |

In a definition with no param, wrappers are followed to the program they start: `env` (options,
`-a`/`--argv0` included, and `NAME=value`), `nice`,
`timeout` (options, then the duration), `stdbuf`, `nohup`, `xargs` (`--eof`, `--replace` and
`--max-lines` take a value only as `=value`), `setsid`, `sudo` (options and
`NAME=value`), `doas`, `chroot` (options, then the new root). A wrapper whose program is a param
(`["env", "{prog}"]`) is refused — the caller would pick the program — and so are the wrappers that
start a shell themselves: `sudo -s`/`-i`/`--shell`/`--login`, `doas -s`, and `chroot <root>` with
no program.

A value is refused (`INVALID_ARGS`) when it names a shell or interpreter from the first two rows,
unless the definition has `allow_shell = true`.

### A param follows only a data-only program (rule A7)

The lists above name programs known to run code; no such list is ever complete (`ionice`,
`taskset`, `chrt`, `flock`, `runuser`, `setpriv`, `unshare`, `nsenter`, `time`, a site's own
script all start the program they are given), and a wrapper's own option parsing is one more
place a value can turn into a program (`xargs --max-lines`, `env -a`, GNU long-option
abbreviations). So a definition with a param, and without `allow_shell = true`, is refused
(`VALIDATION_ERROR`, no ssh call) unless all of this holds:

1. **argv[0] is a data-only program** (by basename, version suffix dropped), with no wrapper before
   it. `nice`, `sudo`, `timeout`, `xargs`, `stdbuf`, `nohup`, `setsid`, `doas`, `chroot`, `ionice`,
   `flock`, `docker exec` and every program not in the table below need `allow_shell = true` as
   soon as the definition has a param. The one prefix allowed is `env` followed only by literal
   `NAME=value` items (`["env", "LC_ALL=C", "grep", "-r", "x", "{dir}"]`): env then reads no option
   and starts the next item, which must itself be a data-only program. `env -i`, `env -u`, `env -a`
   and a param after `env` are refused.
2. **Every literal option is spelled exactly as one the program has.** Each program below has a
   table of its short letters and full long names; a long option written as an abbreviation
   (`--expr`, `--fi`, `--show`), an unknown option, or a value glued onto a long option that takes
   none is refused. A short cluster is read letter by letter (`-sh`, `-ne`), a value-taking letter
   consuming the rest of the cluster or the next item.
3. **A param is an operand or the value of a data option, never code.** A value starting with `-`
   is already refused, so a param is never itself an option. It may fill the value of an option
   that takes data (`tail -n {n}`, `du --max-depth {d}`, `find -name {pattern}`), never the value of
   one that reads code or a script: `sed -e`/`--expression`, `sed -f`/`--file`.

| Data-only program | Options (exact spellings, `-x` short, `--name` long) and constraints |
|---|---|
| `cat` | `-AbeEnstTuv`; `--show-all` `--number-nonblank` `--show-ends` `--number` `--squeeze-blank` `--show-tabs` `--show-nonprinting` |
| `tac` | `-b` `-r` `-s V`; `--before` `--regex` `--separator V` |
| `head` | `-q` `-v` `-z` `-c V` `-n V`; `--quiet` `--silent` `--verbose` `--zero-terminated` `--bytes V` `--lines V` |
| `tail` | `-f` `-F` `-q` `-v` `-z` `-c V` `-n V` `-s V`; `--retry` `--quiet` `--silent` `--verbose` `--zero-terminated` `--bytes V` `--lines V` `--max-unchanged-stats V` `--pid V` `--sleep-interval V` `--follow[=V]` |
| `ls` | `-aAbBcCdDfFgGhHiklLmnNopqQrRsStuUvxXZ1` `-I V` `-T V` `-w V`; the GNU long names (`--all`, `--human-readable`, `--sort V`, `--color[=V]`, ...; see `DATA_PROGRAMS` in `src/ops/exec.ts`) |
| `du` | `-0abcDHhklLmPSsx` `-B V` `-d V` `-t V` `-X V`; `--null` `--all` `--apparent-size` `--bytes` `--total` `--dereference-args` `--human-readable` `--inodes` `--count-links` `--dereference` `--no-dereference` `--separate-dirs` `--si` `--summarize` `--one-file-system` `--block-size V` `--max-depth V` `--files0-from V` `--threshold V` `--time-style V` `--exclude-from V` `--exclude V` `--time[=V]` |
| `df` `stat` `wc` `zcat` `md5sum` `sha1sum` `sha256sum` `readlink` `realpath` `id` `hostname` `uname` `uptime` `free` `ps` `touch` `mkdir` `rmdir` `rm` `cp` `mv` `ln` `chmod` `chown` `date` `journalctl` | each its GNU coreutils / procps / systemd options, exact spellings only (the table per program is `DATA_PROGRAMS` in `src/ops/exec.ts`). Left out on purpose: `journalctl --vacuum-*`/`--rotate`/`--flush`/`-M`, mode-style `chmod -w` (write `chmod a-w`) |
| `grep` `egrep` `fgrep` | `-EFGPiywxzsvcLloqbHhnTZUarR` `-e V` `-f V` `-m V` `-A V` `-B V` `-C V` `-d V` `-D V`, the GNU long names, `--color[=V]`; `-e`/`-f` are data here (a pattern) |
| `echo` | `-n` `-e` `-E` |
| `sed` | `-n` `-E` `-r` `-s` `-u` `-z` `-b` `-l V` `-i[SUFFIX]`; `--quiet` `--silent` `--debug` `--posix` `--regexp-extended` `--separate` `--sandbox` `--unbuffered` `--null-data` `--follow-symlinks` `--binary` `--line-length V` `--in-place[=SUFFIX]`; `-e`/`--expression` and `-f`/`--file` read code, so their value must be literal. The script (every `-e`, or the first operand when there is none) must be literal and must not run a command or touch a file: no `e`, `r`, `R`, `w`, `W`, `s///e`, `s///w` |
| `find` | leading `-H` `-L` `-P` `-O0`..`-O3`; start points (a param may be one); then only these words: tests taking a value (a param may fill it) `-name` `-iname` `-path` `-ipath` `-wholename` `-iwholename` `-regex` `-iregex` `-regextype` `-lname` `-ilname` `-type` `-xtype` `-size` `-perm` `-user` `-group` `-uid` `-gid` `-links` `-inum` `-samefile` `-newer` `-anewer` `-cnewer` `-newerXY` `-atime` `-amin` `-ctime` `-cmin` `-mtime` `-mmin` `-used` `-fstype` `-maxdepth` `-mindepth` `-printf` `-files0-from`, and `-print` `-print0` `-ls` `-prune` `-quit` `-true` `-false` `-empty` `-readable` `-writable` `-executable` `-nouser` `-nogroup` `-xdev` `-mount` `-depth` `-daystart` `-follow` `-noleaf` `-ignore_readdir_race` `-noignore_readdir_race` `-not` `-and` `-or` `-a` `-o` `(` `)` `!` `,`. `-exec` `-execdir` `-ok` `-okdir` `-delete` `-fprint` `-fprint0` `-fprintf` `-fls` and any other word are refused |
| `php` | argv[1] is a literal script path, not an option and not a param (`php artisan {cmd}`, `php /srv/a.php {x}`); no php option at all (`-d`, `-n`, `-r`, `--`, ...). What follows the script is the script's own arguments |
| `docker` | argv[1] is one of `logs` `inspect` `ps` `stats` `top` `port` `diff` `history` `images` `restart` `start` `stop` `kill` `pause` `unpause` `wait`, written literally (no global option such as `-H`/`--context` before it); after it only that subcommand's options: `logs` `-f` `-t` `-n V` `--details` `--follow` `--timestamps` `--since V` `--tail V` `--until V`; `inspect` `-s` `-f V` `--size` `--format V` `--type V`; `ps` `-a` `-l` `-q` `-s` `-f V` `-n V` `--all` `--latest` `--no-trunc` `--quiet` `--size` `--filter V` `--format V` `--last V`; `stats` `-a` `--all` `--no-stream` `--no-trunc` `--format V`; `history` `-H` `-q` `--human` `--no-trunc` `--quiet` `--format V`; `images` `-a` `-q` `-f V` `--all` `--digests` `--no-trunc` `--quiet` `--filter V` `--format V`; `restart`/`stop` `-s V` `-t V` `--signal V` `--time V`; `start` `-a` `-i` `--attach` `--interactive` `--detach-keys V`; `kill` `-s V` `--signal V`; `top` `port` `diff` `pause` `unpause` `wait` none |
| `systemctl` | argv[1] is one of `status` `show` `cat` `is-active` `is-enabled` `is-failed` `list-units` `list-timers` `start` `stop` `restart` `try-restart` `reload` `reload-or-restart`, written literally (so `--user` comes after the verb); then `-a` `-q` `-l` `-n V` `-o V` `-p V` `-t V` `-P V` `--all` `--quiet` `--full` `--no-pager` `--no-legend` `--plain` `--value` `--now` `--no-block` `--no-ask-password` `--system` `--user` `--failed` `--show-types` `--lines V` `--output V` `--property V` `--type V` `--state V` `--job-mode V`. `-H`/`--host` and `-M`/`--machine` are refused |

`git` is not on the list: its aliases, `-c`, pager and textconv settings, and the repository's own
config can each run a program, so a `git` definition with a param needs `allow_shell = true`.
A command inside a container is declared with `container = "<name>"` and the program itself as
`argv[0]`, never as `docker exec <c> ...`. A definition with no param is not affected by this
rule: `["git", "log", "-n", "1"]` and `["nice", "-n", "10", "du", "-sh", "/srv"]` run.

**Behaviour change (fix I).** Before rule A7 a param could follow a program the wrappers above
started, and any option of a data-only program passed. Now a definition with a param behind
`nice`, `sudo`, `timeout`, `xargs`, `stdbuf`, `nohup`, `setsid`, `doas` or `chroot`, with a php
option before the script, with a docker global option, with `systemctl --user` before the verb, or
with an abbreviated or unlisted option needs `allow_shell = true` (or the value written into the
definition). `env NAME=value <data-only program> ...` still runs.

## What every value passes first

Before its type, every value is refused (`INVALID_ARGS`, no ssh call) when it:

- is empty or over 512 bytes (UTF-8);
- contains a NUL, a line break, a tab or any other control character;
- starts with `-` (the program would read it as an option);
- contains a shell metacharacter: `;` `&` `|` a backtick `$` `<` `>` `(` `)` `{` `}` `[` `]` `*` `?` `!` `~` `#`, a quote or a backslash;
- names a shell or interpreter, unless the definition has `allow_shell = true`.

Each value then travels as one single-quoted word.

## How a `path` value reaches the command

The check and the command run in ONE `sh -c` where the command runs (inside the container when the
definition names one; `docker exec <c> sh -c ...`, so the container needs a `sh`, a `test` and a
`realpath` — busybox's are enough). The script resolves `under` and the value with `realpath`,
refuses a value whose resolved path is not under the resolved root (`VALIDATION_ERROR`, the
command never starts), and then:

- on a host with `/proc/self/fd` (Linux, containers included) it opens the resolved directory —
  the file's own directory for a file — on descriptor 3 + N, checks that what it opened is still
  under the root, and hands the command `/proc/self/fd/<3+N>/<name>` (`/proc/self/fd/<3+N>/.` for a
  directory). A directory renamed or swapped for a link after the check cannot redirect the
  command: it reaches the directory already opened. The command sees that path in its own output
  and errors (`grep -r` prints file names under it);
- elsewhere the command receives the resolved path itself, and the window between the check and
  the command's own open stays open.

Outside the guarantee: a concurrent writer under `under` replacing the final name itself (a file
swapped for a link in the directory already opened), and hard links — a hard link under `under` to
a file outside it is the same file, and `realpath` cannot tell.

## Output

`data` is `{name, lines, lines_returned}`: the command's stdout, scrubbed like every other op
(secret-shaped values, PEM key bodies, runs of env-file lines, addresses and the alias identity). A
failing command returns `COMMAND_FAILED` with `remote_exit` and a scrubbed `stderr_tail`. The budget
is 120 s, or the definition's own `timeout`; `--timeout <sec>` overrides either per call.

## Errors

| Code | When |
|---|---|
| `VALIDATION_ERROR` | no file for the alias, a symlinked / foreign-owned / group- or other-readable file, an undeclared name (`did_you_mean`, `next: exec list`), a shell or other code runner without `allow_shell`, an undeclared `container`, a mutating definition through `exec run` (`next: exec change ... --yes`), a path outside `under` (locally or after `realpath`) or missing on the host |
| `CONFIG_PARSE_ERROR` | the file is not valid TOML, or a definition is malformed (unknown field, wrong type, more than 16 params or 7 `path` params, a `timeout` outside 1-1800, a regex that does not compile on its own, a spliced or undeclared `{param}`, a refused default) |
| `INVALID_ARGS` | a value failed a gate or its type, an unknown or repeated param, a missing required one, more than 16 `--param` |
| `CONFIRMATION_REQUIRED` | `exec change` without `--yes` |
| `PROFILE_DENIED` | `exec change` under `SSHEPHERD_PROFILE=read` |
