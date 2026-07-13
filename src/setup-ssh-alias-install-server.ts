import { readTextOrEmpty } from './setup-file-io.ts';

/** Abandoned form (nobody submits) gives up after 3 minutes — see plan.md's assumptions. */
export const DEFAULT_INSTALL_TIMEOUT_MS = 3 * 60 * 1_000;

const INSTALL_CONNECT_TIMEOUT_S = 10;

/** How long `peekTailscaleBanner` waits for the first `\r\n`-terminated line before giving
 *  up and failing soft (treated as "not Tailscale, proceed") — see plan.md Phase 3. */
const BANNER_PEEK_TIMEOUT_MS = 3_000;

/** `ConnectTimeout` for `probeAlreadyTrusted`'s non-interactive `ssh -o BatchMode=yes` probe —
 *  short on purpose so a target that isn't already trusted fails fast instead of stalling
 *  the browser form behind it. */
const PROBE_CONNECT_TIMEOUT_S = 8;

/** Connection target `install` needs — read from the alias's managed ssh-config stanza by
 *  the caller (`setup-ssh-alias.ts`'s `install()`), never re-derived here. */
export interface InstallTarget {
  alias: string;
  host: string;
  user: string;
  port: number;
  publicKeyPath: string;
}

export type InstallOutcome =
  | { kind: 'installed' }
  | { kind: 'already_trusted' }
  | { kind: 'tailscale_detected' }
  | { kind: 'timed_out' }
  | { kind: 'ssh_failed'; exitCode: number }
  | { kind: 'sshpass_not_found' };

/** What a single `sshpass ssh ...` invocation returns — mirrors `transport.ts`'s
 *  `SpawnOutcome` shape (`code` + `timedOut`), minus stdout/stderr, which `install` never
 *  needs to read back. */
export interface SpawnInstallOutcome {
  code: number;
  timedOut: boolean;
}

/** Injected in tests with a fake implementation so `install`'s tests never spawn a real
 *  `sshpass`/`ssh` process — same seam style as `transport.ts`'s `SshRunner`. */
export type SpawnInstallFn = (
  password: string,
  target: InstallTarget,
) => Promise<SpawnInstallOutcome>;

/** Injected in tests with a fake implementation so `install`'s Tailscale pre-check never
 *  opens a real socket — same seam style as `SpawnInstallFn`. Resolves `true` when the
 *  target's banner line matches Tailscale, `false` for everything else (including a peek
 *  that timed out or errored — the check fails soft). */
export type PeekBannerFn = (target: InstallTarget) => Promise<boolean>;

/** Injected in tests with a fake implementation so `install`'s already-trusted pre-check
 *  never spawns a real `ssh` process — same seam style as `SpawnInstallFn`. Resolves `true`
 *  when the target already accepts a key/agent-based connection with no password supplied. */
export type ProbeReachableFn = (target: InstallTarget) => Promise<boolean>;

export interface ServeLikeOptions {
  hostname: string;
  port: number;
  fetch: (req: Request) => Promise<Response> | Response;
}

export interface ServeHandle {
  port: number;
  stop: () => void;
}

/** Injected in tests with a fake implementation that captures the `fetch` handler instead
 *  of opening a real port, so the automated suite can drive GET/POST directly against it. */
export type ServeLikeFn = (options: ServeLikeOptions) => ServeHandle;

export interface InstallServerDeps {
  which: (cmd: string) => string | null;
  peekBanner: PeekBannerFn;
  probeReachable: ProbeReachableFn;
  serve: ServeLikeFn;
  spawnInstall: SpawnInstallFn;
  announceUrl: (url: string) => void;
  randomToken: () => string;
  timeoutMs: number;
}

/** Base64-embeds the public key so the remote shell command never has to escape raw
 *  ssh-key content (which can contain `/` and `+` but never quotes) — decoded back to a
 *  real line on the remote side before being appended. */
function buildRemoteInstallCommand(publicKey: string): string {
  const publicKeyB64 = Buffer.from(publicKey, 'utf8').toString('base64');
  return `mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '${publicKeyB64}' | base64 -d >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`;
}

/** Pure, no password argument at all — proves by construction that the password never
 *  becomes part of the sshpass/ssh argv (it only ever reaches the child process via its
 *  stdin, written separately by `defaultSpawnInstall`). */
export function buildSshpassArgs(target: InstallTarget, remoteCmd: string): string[] {
  return [
    'sshpass',
    '-f',
    '/dev/stdin',
    'ssh',
    '-o',
    'StrictHostKeyChecking=accept-new',
    '-o',
    `ConnectTimeout=${INSTALL_CONNECT_TIMEOUT_S}`,
    '-p',
    String(target.port),
    `${target.user}@${target.host}`,
    remoteCmd,
  ];
}

/** Real `sshpass -f /dev/stdin ssh ...` spawn — password is written to the child's stdin
 *  and immediately closed, never passed via `env`, argv, or written to disk. Mirrors
 *  `transport.ts`'s `defaultRunner` timeout-race shape. Not exercised by `bun test` (see
 *  plan.md's test-seam note); reserved for the manual/live verification step. */
async function defaultSpawnInstall(
  password: string,
  target: InstallTarget,
): Promise<SpawnInstallOutcome> {
  const publicKey = readTextOrEmpty(target.publicKeyPath).trim();
  const remoteCmd = buildRemoteInstallCommand(publicKey);
  const args = buildSshpassArgs(target, remoteCmd);

  const proc = Bun.spawn(args, {
    stdout: 'pipe',
    stderr: 'pipe',
    stdin: 'pipe',
  });
  proc.stdin.write(password);
  proc.stdin.end();

  let timedOut = false;
  const timer = setTimeout(
    () => {
      timedOut = true;
      proc.kill();
    },
    (INSTALL_CONNECT_TIMEOUT_S + 5) * 1_000,
  );

  const code = await proc.exited;
  clearTimeout(timer);

  return { code, timedOut };
}

/**
 * Opens a raw TCP socket to `target.host:target.port` and reads only the first
 * `\r\n`-terminated line (the SSH protocol identification banner per RFC 4253), looking for
 * the (undocumented, empirically observed — see research.md's captured `ssh -v` transcript)
 * `Tailscale` substring. Never invokes `ssh`/`sshpass` — a raw socket peek is the only way to
 * see this banner without triggering Tailscale SSH's own auth-method interception, which is
 * what makes a password/key probe hang instead of failing fast. Fails soft (resolves `false`)
 * on any timeout, connect error, or unexpected close, since an ordinary sshd that isn't
 * Tailscale-fronted must never be misreported as one. Not exercised by `bun test` against a
 * real socket (see plan.md's test-seam note); reserved for the manual/live verification step.
 */
function peekTailscaleBanner(target: InstallTarget): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    let socket: Bun.Socket<undefined> | undefined;
    let buffer = '';

    const finish = (detected: boolean): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      socket?.end();
      resolve(detected);
    };

    const timer = setTimeout(() => finish(false), BANNER_PEEK_TIMEOUT_MS);

    Bun.connect({
      hostname: target.host,
      port: target.port,
      socket: {
        data(_socket, data) {
          buffer += data.toString('utf8');
          const lineEnd = buffer.indexOf('\r\n');
          if (lineEnd !== -1) {
            finish(buffer.slice(0, lineEnd).includes('Tailscale'));
          }
        },
        error: () => finish(false),
        close: () => finish(false),
        connectError: () => finish(false),
      },
    })
      .then((connected) => {
        if (settled) {
          // The timeout/error path already resolved while the connect was in flight —
          // don't leave a socket dangling open past this function's own lifetime.
          connected.end();
          return;
        }
        socket = connected;
      })
      .catch(() => finish(false));
  });
}

/**
 * Non-interactive reachability probe: `ssh -o BatchMode=yes -o ConnectTimeout=<n> -p <port>
 * <user>@<host> -- echo sshepherd-ok` with no password or key ever written to the child's
 * stdin (`stdin: 'ignore'`) — proves whether the target already trusts whatever identity/agent
 * the local `ssh` picks up on its own, with zero new credentials supplied. Mirrors
 * `defaultSpawnInstall`'s spawn+timeout+cleanup shape. `BatchMode=yes` makes a missing
 * key/agent fail immediately instead of hanging on a password prompt with no TTY to answer it.
 * Not exercised by `bun test` against a real `ssh` process (see plan.md's test-seam note);
 * reserved for the manual/live verification step.
 */
async function probeAlreadyTrusted(target: InstallTarget): Promise<boolean> {
  const args = [
    'ssh',
    '-o',
    'BatchMode=yes',
    '-o',
    `ConnectTimeout=${PROBE_CONNECT_TIMEOUT_S}`,
    '-p',
    String(target.port),
    `${target.user}@${target.host}`,
    '--',
    'echo sshepherd-ok',
  ];

  const proc = Bun.spawn(args, {
    stdout: 'ignore',
    stderr: 'ignore',
    stdin: 'ignore',
  });

  let timedOut = false;
  const timer = setTimeout(
    () => {
      timedOut = true;
      proc.kill();
    },
    (PROBE_CONNECT_TIMEOUT_S + 5) * 1_000,
  );

  const code = await proc.exited;
  clearTimeout(timer);

  return !timedOut && code === 0;
}

function defaultAnnounceUrl(url: string): void {
  process.stdout.write(`Open this URL in your browser to install the key: ${url}\n`);
  try {
    const command =
      process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
    Bun.spawn([command, url], { stdout: 'ignore', stderr: 'ignore', stdin: 'ignore' });
  } catch {
    // Best-effort only — the URL is already printed above as the fallback.
  }
}

function defaultServe(options: ServeLikeOptions): ServeHandle {
  const server = Bun.serve({
    hostname: options.hostname,
    port: options.port,
    fetch: options.fetch,
  });
  return { port: server.port ?? options.port, stop: () => server.stop(true) };
}

export function defaultInstallServerDeps(): InstallServerDeps {
  return {
    which: (cmd) => Bun.which(cmd),
    peekBanner: peekTailscaleBanner,
    probeReachable: probeAlreadyTrusted,
    serve: defaultServe,
    spawnInstall: defaultSpawnInstall,
    announceUrl: defaultAnnounceUrl,
    randomToken: () => crypto.randomUUID(),
    timeoutMs: DEFAULT_INSTALL_TIMEOUT_MS,
  };
}

// Inline, no external requests — this page is where a password gets typed, so it never
// loads a third-party stylesheet/script (e.g. a Tailwind CDN), only hand-rolled CSS.
const PAGE_STYLE = `<style>
  :root{color-scheme:dark}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
    background:#0a0e0a;color:#33ff66;
    font-family:ui-monospace,'SF Mono',Menlo,Consolas,'Courier New',monospace}
  .card{width:100%;max-width:420px;margin:1.5rem;padding:2rem 2.25rem;border-radius:4px;
    background:#0d120d;border:1px solid #1f4d2e;box-shadow:0 0 24px rgba(51,255,102,.08)}
  h1{margin:0 0 1rem;font-size:1rem;letter-spacing:.08em;text-transform:uppercase;color:#33ff66}
  p{margin:0;color:#7fdba0;line-height:1.5;font-size:.9rem}
  label{display:block;margin-bottom:1.25rem;color:#7fdba0;font-size:.85rem}
  input[type=password]{width:100%;margin-top:.5rem;padding:.6rem .7rem;border-radius:2px;
    background:#000;border:1px solid #1f4d2e;color:#33ff66;font:inherit;font-size:1rem}
  input[type=password]:focus{outline:none;border-color:#33ff66}
  button{width:100%;margin-top:.25rem;padding:.65rem;border-radius:2px;cursor:pointer;
    background:#122417;border:1px solid #33ff66;color:#33ff66;font:inherit;font-size:.85rem;
    letter-spacing:.08em;text-transform:uppercase}
  button:hover{background:#1a3320}
</style>`;
const FORM_HTML_HEAD = `<!doctype html><html><head><meta charset="utf-8"><title>sshepherd install</title>${PAGE_STYLE}</head><body><div class="card">`;
const FORM_HTML_TAIL = '</div></body></html>';

function renderFormHtml(alias: string, token: string): string {
  return `${FORM_HTML_HEAD}<h1>Install SSH key for '${alias}'</h1><form method="post" action="/${token}/submit"><label>Password<input type="password" name="password" autofocus></label><button type="submit">Install</button></form>${FORM_HTML_TAIL}`;
}

function renderSuccessHtml(): string {
  return `${FORM_HTML_HEAD}<h1>Key installed</h1><p>You can close this tab.</p>${FORM_HTML_TAIL}`;
}

function renderErrorHtml(message: string): string {
  return `${FORM_HTML_HEAD}<h1>Install failed</h1><p>${message}</p>${FORM_HTML_TAIL}`;
}

/**
 * One-shot local browser form: binds `127.0.0.1` only (never `0.0.0.0`) on an ephemeral
 * port, gates every route behind a random per-invocation token (wrong/missing token always
 * 404s — never 403, so the route's existence isn't confirmable), waits for either a
 * password submission or `deps.timeoutMs` of silence, and resolves with a typed outcome.
 * The password itself only ever exists as a local variable inside the POST handler and the
 * argument to `deps.spawnInstall` — it is never returned, logged, or written to disk.
 */
export async function runInstallServer(
  target: InstallTarget,
  overrides: Partial<InstallServerDeps> = {},
): Promise<InstallOutcome> {
  const deps: InstallServerDeps = { ...defaultInstallServerDeps(), ...overrides };

  if (deps.which('sshpass') === null) {
    return { kind: 'sshpass_not_found' };
  }

  const token = deps.randomToken();
  let settled = false;
  let resolveOutcome: (outcome: InstallOutcome) => void = () => {};
  const submittedPromise = new Promise<InstallOutcome>((resolve) => {
    resolveOutcome = resolve;
  });

  const settle = (outcome: InstallOutcome): void => {
    if (settled) {
      return;
    }
    settled = true;
    resolveOutcome(outcome);
  };

  const fetchHandler = async (req: Request): Promise<Response> => {
    const url = new URL(req.url);
    const parts = url.pathname.split('/').filter((part) => part.length > 0);
    const reqToken = parts[0];
    if (reqToken !== token) {
      return new Response('Not Found', { status: 404 });
    }

    if (req.method === 'GET' && parts.length === 1) {
      return new Response(renderFormHtml(target.alias, token), {
        headers: { 'content-type': 'text/html' },
      });
    }

    if (req.method === 'POST' && parts.length === 2 && parts[1] === 'submit') {
      const form = await req.formData();
      const password = form.get('password');
      if (typeof password !== 'string' || password.length === 0) {
        return new Response(renderErrorHtml('Password is required'), {
          status: 400,
          headers: { 'content-type': 'text/html' },
        });
      }

      const spawnResult = await deps.spawnInstall(password, target);
      // `password` goes out of scope here — never referenced again.

      if (spawnResult.timedOut) {
        settle({ kind: 'ssh_failed', exitCode: -1 });
        return new Response(renderErrorHtml('Connection to the remote host timed out'), {
          headers: { 'content-type': 'text/html' },
        });
      }
      if (spawnResult.code === 0) {
        settle({ kind: 'installed' });
        return new Response(renderSuccessHtml(), { headers: { 'content-type': 'text/html' } });
      }
      settle({ kind: 'ssh_failed', exitCode: spawnResult.code });
      return new Response(
        renderErrorHtml('ssh exited with a non-zero status — check the password and try again'),
        {
          headers: { 'content-type': 'text/html' },
        },
      );
    }

    return new Response('Not Found', { status: 404 });
  };

  const handle = deps.serve({ hostname: '127.0.0.1', port: 0, fetch: fetchHandler });
  const url = `http://127.0.0.1:${handle.port}/${token}`;
  deps.announceUrl(url);

  const timeoutPromise = new Promise<InstallOutcome>((resolve) => {
    setTimeout(() => resolve({ kind: 'timed_out' }), deps.timeoutMs);
  });

  const outcome = await Promise.race([submittedPromise, timeoutPromise]);
  settle(outcome);
  handle.stop();

  return outcome;
}
