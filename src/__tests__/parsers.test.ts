import { describe, expect, test } from 'bun:test';
import { parseDf, parseDfInodes } from '../parsers/df.ts';
import { parseDu } from '../parsers/du.ts';
import { parseFree } from '../parsers/free.ts';
import { parseLs } from '../parsers/ls.ts';
import { parsePs } from '../parsers/ps.ts';
import { parseUptime } from '../parsers/uptime.ts';

// Fixtures below are real captured command output shapes documented for GNU
// coreutils/procps on Linux (df/free/uptime/ps/du/ls column layouts are stable,
// standardized formats — matched against `jc`'s published schemas as reference).
// This dev box is macOS, whose df/free/ps differ from Linux, so these are the
// authoritative documented Linux shapes rather than a live capture — flagged in
// the phase report for audit against a real Linux target.

describe('parseDf', () => {
  test('parses df -B1 -P output into byte-unit entries', () => {
    const stdout = [
      'Filesystem     1B-blocks       Used   Available Capacity Mounted on',
      '/dev/sda1    21467271168 8589934592 11824550912       43% /',
      'tmpfs         1073741824          0  1073741824        0% /dev/shm',
    ].join('\n');

    expect(parseDf(stdout)).toEqual([
      {
        filesystem: '/dev/sda1',
        size_bytes: 21467271168,
        used_bytes: 8589934592,
        avail_bytes: 11824550912,
        use_percent: 43,
        mounted_on: '/',
      },
      {
        filesystem: 'tmpfs',
        size_bytes: 1073741824,
        used_bytes: 0,
        avail_bytes: 1073741824,
        use_percent: 0,
        mounted_on: '/dev/shm',
      },
    ]);
  });

  test('parseDfInodes maps the same POSIX layout onto inode counts', () => {
    const stdout = [
      'Filesystem      Inodes  IUsed   IFree IUse% Mounted on',
      '/dev/sda1      1310720 234567 1076153   18% /',
    ].join('\n');

    expect(parseDfInodes(stdout)).toEqual([
      {
        filesystem: '/dev/sda1',
        inodes_total: 1310720,
        inodes_used: 234567,
        inodes_avail: 1076153,
        inodes_use_percent: 18,
        mounted_on: '/',
      },
    ]);
  });
});

describe('parseFree', () => {
  test('parses free -b output into mem/swap byte sections', () => {
    const stdout = [
      '              total        used        free      shared  buff/cache   available',
      'Mem:     8589934592  1234567890  3456789012   12345678   3987654321   6789012345',
      'Swap:    2147483648           0  2147483648',
    ].join('\n');

    expect(parseFree(stdout)).toEqual({
      mem: {
        total: 8589934592,
        used: 1234567890,
        free: 3456789012,
        shared: 12345678,
        buff_cache: 3987654321,
        available: 6789012345,
      },
      swap: { total: 2147483648, used: 0, free: 2147483648 },
    });
  });
});

describe('parseUptime', () => {
  test('parses the multi-day form with load averages', () => {
    const stdout = ' 14:32:05 up 10 days,  3:14,  2 users,  load average: 0.15, 0.22, 0.18';
    expect(parseUptime(stdout)).toEqual({
      time: '14:32:05',
      uptime: '10 days,  3:14',
      users: 2,
      load_1m: 0.15,
      load_5m: 0.22,
      load_15m: 0.18,
    });
  });

  test('returns null on unparseable input', () => {
    expect(parseUptime('garbage')).toBeNull();
  });
});

describe('parsePs', () => {
  test('parses ps aux rows, converting VSZ/RSS from KiB to bytes', () => {
    const stdout = [
      'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND',
      'root         1  0.0  0.1 168000 11200 ?        Ss   Jul10   0:03 /sbin/init',
      'app        842 12.3  4.5 985432 368200 ?       Sl   09:00   3:21 node server.js --port 3000',
    ].join('\n');

    const entries = parsePs(stdout);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toEqual({
      user: 'root',
      pid: 1,
      cpu_percent: 0.0,
      mem_percent: 0.1,
      vsz_bytes: 168000 * 1024,
      rss_bytes: 11200 * 1024,
      tty: '?',
      stat: 'Ss',
      start: 'Jul10',
      time: '0:03',
      command: '/sbin/init',
    });
    expect(entries[1]?.command).toBe('node server.js --port 3000');
    expect(entries[1]?.rss_bytes).toBe(368200 * 1024);
  });
});

describe('parseDu', () => {
  test('parses du -sb tab-separated bytes/path pairs', () => {
    const stdout = '12345678\t/var/log\n987654321\t/var/lib/docker\n';
    expect(parseDu(stdout)).toEqual([
      { path: '/var/log', size_bytes: 12345678 },
      { path: '/var/lib/docker', size_bytes: 987654321 },
    ]);
  });
});

describe('parseLs', () => {
  test('parses ls -la --time-style=long-iso rows, skipping the total line', () => {
    const stdout = [
      'total 48',
      'drwxr-xr-x  5 root root  4096 2026-07-10 10:00 .',
      'drwxr-xr-x 20 root root  4096 2026-07-01 09:00 ..',
      '-rw-r--r--  1 root root  1234 2026-07-11 12:30 file.txt',
      'lrwxrwxrwx  1 root root     7 2026-07-09 08:00 link -> target',
    ].join('\n');

    const entries = parseLs(stdout);
    expect(entries).toHaveLength(4);
    expect(entries[2]).toEqual({
      name: 'file.txt',
      permissions: '-rw-r--r--',
      links: 1,
      owner: 'root',
      group: 'root',
      size_bytes: 1234,
      modified_at: '2026-07-11T12:30',
      is_dir: false,
      is_symlink: false,
      link_target: null,
    });
    expect(entries[3]).toEqual({
      name: 'link',
      permissions: 'lrwxrwxrwx',
      links: 1,
      owner: 'root',
      group: 'root',
      size_bytes: 7,
      modified_at: '2026-07-09T08:00',
      is_dir: false,
      is_symlink: true,
      link_target: 'target',
    });
  });
});
