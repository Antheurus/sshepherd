import { describe, expect, test } from 'bun:test';
import { maskPemLines, type ScrubOptions, scrub, scrubText } from '../scrub.ts';

const text = (input: string, options: ScrubOptions): string => scrubText(input, options).value;

describe('the alias port in a key that holds a port', () => {
  const options: ScrubOptions = { identity: { port: '2222' } };
  test.each([
    ['SSH_PORT=2222', 'SSH_PORT=<port>'],
    ['PGPORT: 2222', 'PGPORT: <port>'],
    ['{"ssh_port": 2222}', '{"ssh_port": <port>}'],
    ['{"HostIp":"0.0.0.0","HostPort":"2222"}', '{"HostIp":"0.0.0.0","HostPort":"<port>"}'],
    ['2222/udp open', '<port>/udp open'],
  ])('%s', (input, expected) => {
    expect(text(input, options)).toBe(expected);
  });

  test('another number under a port key, and the port under a non-port key, stay', () => {
    const line = 'SSH_PORT=22 report: 2222 export=2222 PGPORT=22220';
    expect(text(line, options)).toBe(line);
  });

  test('a JSON string port under a port key becomes <port>; a numeric one stays a number', () => {
    const { value } = scrub(
      { HostPort: '2222', local_port: 2222, Ports: { '2222/tcp': [{ HostPort: '2222' }] } },
      options,
    );
    expect(value as unknown).toEqual({
      HostPort: '<port>',
      local_port: 2222,
      Ports: { '<port>/tcp': [{ HostPort: '<port>' }] },
    });
  });
});

describe('a joined `pass` name is a password only when its value is not a boolean word', () => {
  test.each([
    'bypass=true',
    'compass: off',
    'trespass=no',
    'firstPass: false',
    'passkey: enabled',
    '{"bypass": "yes"}',
  ])('%s stays visible', (input) => {
    expect(text(input, {})).toBe(input);
  });

  test.each([
    ['dbpass=hunter2-x9', 'dbpass=***'],
    ['firstPass: hunter2-x9', 'firstPass: ***'],
    ['passkey=4b825dc642cb6eb9a060e54bf8d69288', 'passkey=***'],
    ['DB_PASS=true', 'DB_PASS=***'],
    ['smtp_pass: yes', 'smtp_pass: ***'],
    ['--dbpass hunter2-x9', '--dbpass ***'],
  ])('%s is masked', (input, expected) => {
    expect(text(input, {})).toBe(expected);
  });

  test('JSON: a boolean under a joined `pass` name stays, a string password does not', () => {
    const { value } = scrub({ bypass: true, compass: 'off', dbpass: 'hunter2-x9', passkey: 1 }, {});
    expect(value as unknown).toEqual({ bypass: true, compass: 'off', dbpass: '***', passkey: 1 });
  });
});

describe('a common-word user is masked only where it names who connects', () => {
  const options: ScrubOptions = { identity: { user: 'app', hostname: 'srv-01.example.net' } };
  test.each([
    [
      'sshd: Accepted publickey for app from 192.0.2.4 port 50000 ssh2',
      'sshd: Accepted publickey for <user> from 192.0.2.4 port 50000 ssh2',
    ],
    [
      'Failed password for invalid user app from 192.0.2.4',
      'Failed password for invalid user <user> from 192.0.2.4',
    ],
    ['session opened for user app(uid=1001)', 'session opened for user <user>(uid=1001)'],
    ['ssh app@srv-01.example.net', 'ssh <user>@<host>'],
    ['ssh app@192.0.2.4', 'ssh <user>@192.0.2.4'],
    ['ssh -l app web-01', 'ssh -l <user> web-01'],
    ['{"user":"app"}', '{"user":"<user>"}'],
  ])('%s', (input, expected) => {
    expect(text(input, options)).toBe(expected);
  });

  test.each([
    'getty@tty1.service and app@foo.service',
    'cwd /srv/app/releases/42 owned by app',
    'deploy finished for app in 12s',
  ])('%s is left as written', (input) => {
    expect(text(input, options)).toBe(input);
  });
});

describe('IPv6 identity and addresses', () => {
  test('the compressed form of an expanded alias address is <host>', () => {
    const options: ScrubOptions = { identity: { hostname: '2001:db8:0:0:0:0:0:10' } };
    expect(text('peer 2001:db8::10 and [2001:db8::11]:22', options)).toBe(
      'peer <host> and [2001:db8::11]:22',
    );
  });

  test('src: and ipv6: are labels; a MAC and a time after a label stay', () => {
    expect(
      text('src:2001:db8::5 ipv6:2001:db8::5 ether:aa:bb:cc:dd:ee:ff at:12:34:56', {
        maskAddresses: true,
      }),
    ).toBe('src:<ip-1> ipv6:<ip-1> ether:aa:bb:cc:dd:ee:ff at:12:34:56');
  });
});

describe('a lone prefixed END whose BEGIN was cut off', () => {
  const BODY = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2';
  test('timestamps tick between lines and the last body line is short', () => {
    const out = maskPemLines([
      `2026-11-27T10:00:01Z INFO ${BODY}`,
      '2026-11-27T10:00:02Z INFO QUJD',
      '2026-11-27T10:00:03Z INFO -----END RSA PRIVATE KEY-----',
    ]);
    expect(out.slice(0, 2)).toEqual(['***', '***']);
  });

  test('prose ending in an END marker under a log prefix masks nothing', () => {
    const lines = ['web-1  | keys look like this one', 'web-1  | -----END RSA PRIVATE KEY-----'];
    expect(maskPemLines(lines)).toEqual(lines);
  });
});
