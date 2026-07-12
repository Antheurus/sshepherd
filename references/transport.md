# Transport — the zero-knowledge SSH model

Deep reference for `src/transport.ts`. Read this before touching anything that talks to a
remote host, or when debugging a `SshErrorCode` that doesn't look right.

## Why shell out to `ssh`, never `ssh2`

sshepherd shells out to the system `ssh` binary via `Bun.spawn` — it does not use the
`ssh2` npm library. Two independent reasons, both load-bearing:

1. **Credential handling stays outside this process entirely.** Key material, ssh-agent
   handshakes, and `~/.ssh/config` resolution (including `Include`/`Match`/`ProxyJump`)
   all happen inside OpenSSH's own trusted code path. sshepherd never reads a private key,
   never negotiates auth itself, never even resolves the alias to a host/user/port in a
   variable it could accidentally serialize. This is the entire basis of the
   zero-knowledge claim — it isn't a redaction layer bolted onto a client that *could* see
   credentials, it's a design that structurally never has them.
2. **`ssh2` doesn't parse `~/.ssh/config` the way OpenSSH does**, and its optional native
   addon (`cpu-features`, a `.node` binary) breaks `bun build --compile` (this bit
   real projects: `oven-sh/bun#11947`, `opennextjs-cloudflare#1226`). Shelling out avoids
   both problems for free.

`ssh-agent` works via the inherited `SSH_AUTH_SOCK` environment variable — sshepherd wires
nothing for it.

## ControlMaster lifecycle

Every alias reuses one multiplexed connection instead of reconnecting per op:

```
# open (or reuse) the master — background, no command:
ssh -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR \
    -o ControlMaster=auto -o ControlPath=<socket> -o ControlPersist=60 \
    -M -N -f <alias>

# every op reuses it:
ssh -o BatchMode=yes -o LogLevel=ERROR -o ControlPath=<socket> <alias> -- timeout <n> <remote-cmd>

# the CLI tears it down on exit:
ssh -o ControlPath=<socket> -O exit <alias>
```

`ensureMaster` (`transport.ts`) checks the socket first (`-O check`); if that fails it
defensively clears any stale socket left behind by a crashed prior run (`-O exit`, errors
ignored) before opening a fresh master. `validateAlias` runs `ssh -G <alias>` first and
only checks its exit status and that stdout is non-empty — the dumped `HostName`/`User`/
`Port`/`IdentityFile` fields are never parsed into a variable that could leak, presence is
the only thing that matters.

Socket path rules, all load-bearing:

- Lives under `$XDG_RUNTIME_DIR/sshepherd` (falls back to the OS tmpdir).
- Named from `Bun.hash.crc32(alias)` — opaque, short, deterministic per alias. **Never**
  `%h`/`%r`/`%p` tokens (those literally embed host/user/port into the filename).
- Must stay under 100 characters total — macOS caps a Unix-domain socket path at ~104
  bytes (Linux at 108); `socketPath()` throws rather than silently truncating.
- The socket directory is created `0700` (private).

`ControlPersist=60` means the master survives 60s after the CLI process exits even if
`closeMaster` isn't called — a deliberate backstop, not a substitute for calling it.

## The remote command itself

Every op's command is wrapped in a remote `timeout <timeoutSec>` — this kills a genuinely
hung remote process, not just local abandonment of the connection. Local wall-clock abort
adds a small buffer (`LOCAL_TIMEOUT_BUFFER_MS`) on top of the remote timeout so the local
side never fires first.

`-o BatchMode=yes` is mandatory on every invocation: a spawned child process can't answer
an interactive prompt (password, host-key confirmation, passphrase), so BatchMode makes
ssh fail fast instead of hanging forever. For the same reason sshepherd never passes `-t`
(no pseudo-tty) and never sets `-o StrictHostKeyChecking=no` (that would silently accept
an unknown or changed host key — the opposite of what a security tool should do).

## Error classification (`classify` in `transport.ts`)

`ssh` exits **255** for its own transport failures; any other non-zero exit is the *remote
command's* exit code, passed straight through.

| `SshErrorCode` | Detected when |
|---|---|
| `UNKNOWN_ALIAS` | `ssh -G <alias>` fails or returns nothing — checked before any connection |
| `CONNECT_TIMEOUT` | exit 255 + stderr matches `connection timed out\|operation timed out` |
| `AUTH_FAILED` | exit 255 + stderr matches `permission denied\|too many authentication failures` |
| `HOST_KEY_MISMATCH` | exit 255 + stderr matches `remote host identification has changed` |
| `SSH_TRANSPORT_ERROR` | exit 255, none of the above — an unclassified transport failure |
| `COMMAND_FAILED` | any other non-zero exit code — `error.remote_exit` carries it |
| `COMMAND_TIMEOUT` | the local wall-clock timer fired (`timedOut: true`) |
| `CONFIRMATION_REQUIRED` | a mutating op ran without `--yes` — `confirmGate` refuses before any ssh call at all, so this code never touches the classifier |

Classification reads `raw.transportStderr` **only** to pick the code — never to build the
`ErrorInfo.message`. `ERROR_MESSAGES` in `transport.ts` is a fixed per-code string; the raw
stderr text is discarded immediately after classification runs. There is deliberately no
redaction allowlist here: OpenSSH's stderr phrasing varies by version and locale, so any
allowlist would eventually miss a hostname or IP buried in an unfamiliar message. Discard
entirely is the only shape that can't leak.

`RawResult.transportStderr` vs `RawResult.commandStderr`: `run()` only populates
`transportStderr` when ssh itself exited 255 (its own failure); for any other exit code
that same stderr text is treated as the *remote command's* stderr and stored in
`commandStderr` instead — which an op's `shapeError` may read (from `raw.stdout`, not
stderr) for structured failure context, but `commandStderr` itself is still never copied
into an `ErrorInfo` or an `Envelope`.

## The alias-only hygiene rule

Nothing in this codebase ever holds a hostname, IP, username, or port in a variable that
escapes the transport layer — not a log line, not an error message, not a field on the
`Envelope`. The only identity string that crosses the boundary back to a caller is the
alias itself, which the caller supplied in the first place. If a future change needs to
surface *any* connection detail (a resolved IP for a status page, say), that is a
deliberate architecture change requiring explicit sign-off — not an incremental addition,
because it breaks the zero-knowledge guarantee this whole transport layer exists to
provide.
