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
| `allow_shell` | no | `true` lets argv name a shell (`sh`, `bash`, `dash`, `zsh`, `ksh`, `mksh`, `ash`, `yash`, `fish`, `csh`, `tcsh`, `busybox`) anywhere; off by default |
| `params.<name>` | no | at most 16; each one must be used in argv |

A param fills one whole argv element, written exactly `"{name}"`. `"--file={name}"` is a definition
error: splicing a value into a larger string is how one value becomes two meanings.

### Param types

| `type` | Fields | A value passes when |
|---|---|---|
| `enum` | `values = [...]` | it is one of the values |
| `int` | `min`, `max` (whole numbers, 0 <= min <= max) | it is a whole number in range |
| `path` | `under = "/abs/dir"` | it is absolute, has no `.`/`..` segment, lies under `under`, AND its `realpath` on the host (inside the container when the definition names one) still lies under `realpath(under)` |
| `regex` | `pattern = '...'` | it matches the whole pattern |
| `container` | — | it is in the alias's declared `containers` |

`default` (any type) is used when the call omits the param, and is checked like a passed value when
the file is read. A param without a default is required.

## What every value passes first

Before its type, every value is refused (`INVALID_ARGS`, no ssh call) when it:

- is empty or over 512 bytes (UTF-8);
- contains a NUL, a line break, a tab or any other control character;
- starts with `-` (the program would read it as an option);
- contains a shell metacharacter: `;` `&` `|` a backtick `$` `<` `>` `(` `)` `{` `}` `[` `]` `*` `?` `!` `~` `#`, a quote or a backslash;
- names a shell, unless the definition has `allow_shell = true`.

Each value then travels as one single-quoted word. A `path` value is resolved on the host and the
command receives the resolved path; a symbolic link out of `under` stops the command before it
starts (`VALIDATION_ERROR`).

## Output

`data` is `{name, lines, lines_returned}`: the command's stdout, scrubbed like every other op
(secret-shaped values, PEM key bodies, runs of env-file lines, addresses and the alias identity). A
failing command returns `COMMAND_FAILED` with `remote_exit` and a scrubbed `stderr_tail`. The budget
is 120 s; `--timeout <sec>` raises it per call.

## Errors

| Code | When |
|---|---|
| `VALIDATION_ERROR` | no file for the alias, a symlinked / foreign-owned / group- or other-readable file, an undeclared name (`did_you_mean`, `next: exec list`), a shell without `allow_shell`, an undeclared `container`, a mutating definition through `exec run` (`next: exec change ... --yes`), a path outside `under` (locally or after `realpath`) or missing on the host |
| `CONFIG_PARSE_ERROR` | the file is not valid TOML, or a definition is malformed (unknown field, wrong type, more than 16 params, a spliced or undeclared `{param}`, a refused default) |
| `INVALID_ARGS` | a value failed a gate or its type, an unknown or repeated param, a missing required one, more than 16 `--param` |
| `CONFIRMATION_REQUIRED` | `exec change` without `--yes` |
| `PROFILE_DENIED` | `exec change` under `SSHEPHERD_PROFILE=read` |
