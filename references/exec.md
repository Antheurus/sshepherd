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
| `allow_shell` | no | `true` lets argv run a shell or interpreter (the list under [Code runners](#code-runners-need-allow_shell)); off by default |
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
| always | interpreters: `perl` `python` (`python2`, `python3`, `python3.x`) `ruby` `node` `nodejs` `deno` `bun` `lua` `tclsh` `wish` `awk` `gawk` `mawk` `nawk`, and `ssh` (its command runs in the remote shell) |
| with a code option | `php -r`/`-B`/`-R`/`-E` (and `--run`, `--process-begin`, `--process-code`, `--process-end`) before the script; `php artisan ...` runs |
| | `find` with `-exec`, `-execdir`, `-ok`, `-okdir` or `-delete` |
| | `git` with `-c` or `--exec-path`/`--config-env` before the subcommand, `--upload-pack`/`--receive-pack`, or any `core.*` argument |
| | `tar` with `--to-command`, `--use-compress-program`, `--checkpoint-action`, `--info-script`, `--new-volume-script`, `--rsh-command`, `--rmt-command` (any unambiguous abbreviation), or `I`/`F` in a short-option cluster (`-I`, `-xIf`, old-style `xIf`) |
| | `rsync` with `-e`/`--rsh` or `--rsync-path`; `scp` with `-S`, `-o` or `-F` |
| | GNU `sed` whose script holds the `e` command or an `s///e` flag, or whose script (or `-f` file) is a param |
| | `env -S`/`--split-string` |

Wrappers are followed to the program they start: `env` (options and `NAME=value`), `nice`,
`timeout` (options, then the duration), `stdbuf`, `nohup`, `xargs`, `setsid`, `sudo` (options and
`NAME=value`), `doas`, `chroot` (options, then the new root). A wrapper whose program is a param
(`["env", "{prog}"]`) is refused — the caller would pick the program — and so are the wrappers that
start a shell themselves: `sudo -s`/`-i`/`--shell`/`--login`, `doas -s`, and `chroot <root>` with
no program.

A value is refused (`INVALID_ARGS`) when it names a shell or interpreter from the first two rows,
unless the definition has `allow_shell = true`.

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
