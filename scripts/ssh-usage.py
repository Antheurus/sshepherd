#!/usr/bin/env python3
"""Raw ssh vs sshepherd, per intent bucket, from the local Claude Code transcripts.

Every Bash tool call in ~/.claude/projects/**/*.jsonl (subagent transcripts included) is parsed with the
ssh-secret-guard hook's own shell parser and classifier, so this report and the hook can never disagree
about what a command is. A raw ssh call lands in the bucket of the sshepherd group whose op the hook
would name (its deny class's group when it would deny, `uncovered` when no op covers it); an sshepherd
call lands in its own group. The report holds counts only — never a command, host, path or credential.

    python3 scripts/ssh-usage.py [--since YYYY-MM-DD] [--out FILE] [--projects DIR ...] [--guard FILE]

Exit codes: 0 report written, 2 bad input (date, --out inside this repo, guard hook missing), 1 internal.
"""
import argparse
import datetime
import importlib.util
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOME = os.path.expanduser('~')
DEFAULT_GUARD = os.path.join(HOME, '.claude', 'hooks', 'ssh-secret-guard.py')
DEFAULT_GAPS = os.path.join(HOME, '.local', 'state', 'sshepherd', 'gaps.jsonl')
# The three account homes share one projects directory through symlinks; every file is counted once by
# its real path, so listing all of them is harmless and survives the links being replaced by real dirs.
DEFAULT_ROOTS = [os.path.join(HOME, d, 'projects') for d in ('.claude', '.claude-akun2', '.claude-akun3')]
# A transcript line above this is a huge tool result, never a Bash call; reading it whole would make
# the scan's memory follow the largest output ever captured instead of staying flat.
MAX_LINE_BYTES = 8 * 1024 * 1024
DENY_BUCKET = {'sshpass_password': 'setup', 'secret_read': 'env', 'host_key_bypass': 'hosts'}
PREFILTER = (b'ssh', b'scp', b'sftp', b'rsync')
# `sshepherd "$@"` in a wrapper script names no group; anything outside these is counted as `other`.
GROUPS = {'hosts', 'check', 'logs', 'services', 'files', 'env', 'config', 'db', 'deploy', 'security', 'tunnel',
          'audit', 'http', 'wait', 'git', 'exec', 'setup', 'doctor'}


def load_guard(path):
    if not os.path.isfile(path):
        raise SystemExit(usage_error('the guard hook %s is missing; this report classifies with it' % path))
    spec = importlib.util.spec_from_file_location('ssh_secret_guard', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def usage_error(msg):
    print('ssh-usage: %s' % msg, file=sys.stderr)
    return 2


def bounded_lines(fh):
    while True:
        line = fh.readline(MAX_LINE_BYTES)
        if not line:
            return
        if len(line) == MAX_LINE_BYTES and not line.endswith(b'\n'):
            while True:
                rest = fh.readline(MAX_LINE_BYTES)
                if not rest or rest.endswith(b'\n'):
                    break
            yield None
            continue
        yield line


def bash_commands(entry):
    message = entry.get('message')
    content = message.get('content') if isinstance(message, dict) else None
    for block in content if isinstance(content, list) else []:
        if isinstance(block, dict) and block.get('type') == 'tool_use' and block.get('name') == 'Bash':
            args = block.get('input') if isinstance(block.get('input'), dict) else {}
            command = args.get('command')
            if isinstance(command, str):
                yield block.get('id') or '', command


def sshepherd_groups(guard, command):
    """sshepherd invocations in a command, by group; None when the command does not parse."""
    try:
        pipelines, subs = guard.split_segments(command)
    except ValueError:
        return None
    groups = []
    for text in subs:
        groups.extend(sshepherd_groups(guard, text) or [])
    for pipeline in pipelines:
        for seg in pipeline:
            _, words = guard.strip_wrappers(seg['words'])
            if words and os.path.basename(words[0]) == 'sshepherd' and len(words) > 1:
                if not words[1].startswith('-'):
                    groups.append(words[1] if words[1] in GROUPS else 'other')
    return groups


def raw_bucket(guard, command):
    """(bucket, deny class or None) for a raw ssh call, None when the command runs no ssh."""
    v = guard.Verdict()
    try:
        guard.analyze_text(command, v, 0)
    except ValueError:
        return None
    if not v.ran_ssh:
        return None
    if v.denies:
        cls = v.denies[0][0]
        return DENY_BUCKET[cls], cls
    groups = [h.split()[1] for h in v.hints]
    named = [g for g in groups if g != 'setup']
    if named or groups:
        return (named or groups)[0], None
    return 'uncovered', None


def scan(args, guard):
    since = args.since
    since_epoch = datetime.datetime.strptime(since, '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc).timestamp()
    seen_files = set()
    seen_calls = set()
    raw = {}
    shep = {}
    denied = {}
    stats = {'files_scanned': 0, 'files_older_than_since': 0, 'bytes_scanned': 0, 'lines_oversized_skipped': 0,
             'bash_calls_considered': 0, 'unparsed_calls': 0}
    for root in args.projects:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            for name in filenames:
                if not name.endswith('.jsonl'):
                    continue
                path = os.path.realpath(os.path.join(dirpath, name))
                if path in seen_files:
                    continue
                seen_files.add(path)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                if st.st_mtime < since_epoch:
                    stats['files_older_than_since'] += 1
                    continue
                stats['files_scanned'] += 1
                stats['bytes_scanned'] += st.st_size
                with open(path, 'rb') as fh:
                    for line in bounded_lines(fh):
                        if line is None:
                            stats['lines_oversized_skipped'] += 1
                            continue
                        if b'"Bash"' not in line or not any(p in line for p in PREFILTER):
                            continue
                        try:
                            entry = json.loads(line)
                        except ValueError:
                            continue
                        if str(entry.get('timestamp', ''))[:10] < since:
                            continue
                        for call_id, command in bash_commands(entry):
                            if call_id in seen_calls:
                                continue
                            seen_calls.add(call_id)
                            if not guard.TRANSPORT_RE.search(command):
                                continue
                            stats['bash_calls_considered'] += 1
                            groups = sshepherd_groups(guard, command)
                            if groups is None:
                                stats['unparsed_calls'] += 1
                                continue
                            for g in groups:
                                shep[g] = shep.get(g, 0) + 1
                            hit = raw_bucket(guard, command)
                            if hit:
                                bucket, cls = hit
                                raw[bucket] = raw.get(bucket, 0) + 1
                                if cls:
                                    denied[cls] = denied.get(cls, 0) + 1
    return raw, shep, denied, stats


def ratio_row(r, s):
    return {
        'raw': r,
        'sshepherd': s,
        'sshepherd_share': round(s / (r + s), 4) if r + s else None,
        'raw_per_sshepherd': round(r / s, 4) if s else None,
    }


def read_gaps(path):
    counts = {}
    if not os.path.isfile(path):
        return counts
    with open(path, 'rb') as fh:
        for line in bounded_lines(fh):
            try:
                intent = json.loads(line).get('intent') if line else None
            except ValueError:
                continue
            if isinstance(intent, str):
                counts[intent] = counts.get(intent, 0) + 1
    return counts


def main(argv):
    p = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    p.add_argument('--since', default='2026-07-14', help='first day counted, YYYY-MM-DD (default 2026-07-14)')
    p.add_argument('--out', help='write the JSON report here as well (outside this repo)')
    p.add_argument('--projects', nargs='+', default=DEFAULT_ROOTS, help='transcript roots to scan')
    p.add_argument('--guard', default=os.environ.get('SSHEPHERD_GUARD') or DEFAULT_GUARD,
                   help='the ssh-secret-guard hook whose classifier is used')
    p.add_argument('--gaps', default=DEFAULT_GAPS, help='the hook gap log to summarise')
    args = p.parse_args(argv)
    try:
        datetime.datetime.strptime(args.since, '%Y-%m-%d')
    except ValueError:
        return usage_error('--since must be YYYY-MM-DD, got %r' % args.since)
    out = None
    if args.out:
        out = os.path.realpath(os.path.expanduser(args.out))
        if out == REPO or out.startswith(REPO + os.sep):
            return usage_error('--out %s is inside the repo; the report stays out of version control' % args.out)
    guard = load_guard(args.guard)

    raw, shep, denied, stats = scan(args, guard)
    buckets = {b: ratio_row(raw.get(b, 0), shep.get(b, 0)) for b in sorted(set(raw) | set(shep))}
    report = {
        'schema': 1,
        'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
        'since': args.since,
        'scan': stats,
        'totals': ratio_row(sum(raw.values()), sum(shep.values())),
        'buckets': buckets,
        'raw_would_be_denied': dict(sorted(denied.items())),
        'gaps_logged': dict(sorted(read_gaps(args.gaps).items())),
    }
    text = json.dumps(report, indent=2) + '\n'
    if out:
        os.makedirs(os.path.dirname(out), mode=0o700, exist_ok=True)
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(text)
    print('%-10s %8s %10s %8s' % ('bucket', 'raw', 'sshepherd', 'share'))
    for name, row in list(buckets.items()) + [('TOTAL', report['totals'])]:
        share = '-' if row['sshepherd_share'] is None else '%.1f%%' % (row['sshepherd_share'] * 100)
        print('%-10s %8d %10d %8s' % (name, row['raw'], row['sshepherd'], share))
    if out:
        print('report: %s' % out)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except SystemExit:
        raise
    except Exception as exc:
        print('ssh-usage: internal error: %s: %s' % (type(exc).__name__, exc), file=sys.stderr)
        sys.exit(1)
