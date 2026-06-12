import { afterEach, describe, expect, it } from 'vitest';
import { createServer as createTlsServer, type Server as TlsServerType } from 'node:tls';
import { createHash } from 'node:crypto';
import { AddressInfo } from 'node:net';
// Pulled in as a devDependency only — @sharegrid/shared has zero runtime deps.
// We use it here to produce a real PEM cert/key for end-to-end pinning tests.
// eslint-disable-next-line @typescript-eslint/no-var-requires
import selfsigned from 'selfsigned';

import {
  computeFingerprint,
  connectWithPinnedFingerprint,
  FINGERPRINT_PREFIX,
  FINGERPRINT_REGEX,
  parseFingerprintFromUrl,
  formatEndpoint,
  parseEndpoint,
  isIPv6,
} from '../../src/tls.js';
import { TlsFingerprintError, RoleKeyMissingError } from '../../src/errors.js';

interface SelfSignedPems {
  cert: string;
  private: string;
}

function makeSelfSigned(): SelfSignedPems {
  const pems = selfsigned.generate(
    [{ name: 'commonName', value: 'sharegrid-test' }],
    { days: 1, keySize: 2048, algorithm: 'sha256' },
  );
  return { cert: pems.cert, private: pems.private };
}

describe('parseFingerprintFromUrl', () => {
  const goodFingerprint = `${FINGERPRINT_PREFIX}${'a'.repeat(64)}`;
  const goodKey = 'testRoleKey123';
  const goodUrl = `https://router.example.com:8443?fp=${goodFingerprint}&key=${goodKey}`;

  it('extracts host, port, fingerprint, roleKey, and mode from a well-formed URL', () => {
    const parsed = parseFingerprintFromUrl(goodUrl);
    expect(parsed).toEqual({
      host: 'router.example.com',
      port: 8443,
      fingerprint: goodFingerprint,
      roleKey: goodKey,
      mode: 'lan',
    });
  });

  it('defaults mode to lan when the mode param is absent', () => {
    expect(parseFingerprintFromUrl(goodUrl).mode).toBe('lan');
  });

  it('parses mode=internet and strips brackets from an IPv6 host', () => {
    const parsed = parseFingerprintFromUrl(
      `https://[2001:db8::1]:8443?fp=${goodFingerprint}&key=${goodKey}&mode=internet`,
    );
    expect(parsed.host).toBe('2001:db8::1');
    expect(parsed.port).toBe(8443);
    expect(parsed.mode).toBe('internet');
  });

  it('rejects an unknown mode value', () => {
    expect(() =>
      parseFingerprintFromUrl(`https://h:1?fp=${goodFingerprint}&key=${goodKey}&mode=wan`),
    ).toThrow(/mode parameter/);
  });

  it('normalises uppercase fingerprints to lowercase', () => {
    const upper = `${FINGERPRINT_PREFIX}${'A'.repeat(64)}`;
    const parsed = parseFingerprintFromUrl(`https://h:1?fp=${upper}&key=${goodKey}`);
    expect(parsed.fingerprint).toBe(`${FINGERPRINT_PREFIX}${'a'.repeat(64)}`);
  });

  it('rejects a URL without an fp query parameter', () => {
    expect(() => parseFingerprintFromUrl(`https://h:1?key=${goodKey}`)).toThrowError(/fp=sha256/);
  });

  it('rejects a URL whose fp value is the wrong format', () => {
    expect(() => parseFingerprintFromUrl(`https://h:1?fp=md5:abcd&key=${goodKey}`)).toThrowError(/sha256:/);
    expect(() => parseFingerprintFromUrl(`https://h:1?fp=sha256:${'g'.repeat(64)}&key=${goodKey}`)).toThrowError(
      /sha256:/,
    );
    expect(() => parseFingerprintFromUrl(`https://h:1?fp=sha256:${'a'.repeat(63)}&key=${goodKey}`)).toThrowError(
      /sha256:/,
    );
  });

  it('throws RoleKeyMissingError when the key query parameter is absent', () => {
    expect(() => parseFingerprintFromUrl(`https://h:1?fp=${goodFingerprint}`)).toThrow(RoleKeyMissingError);
  });

  it('throws RoleKeyMissingError when the key parameter is empty', () => {
    expect(() => parseFingerprintFromUrl(`https://h:1?fp=${goodFingerprint}&key=`)).toThrow(RoleKeyMissingError);
  });

  it('rejects a URL without an explicit port', () => {
    expect(() => parseFingerprintFromUrl(`https://h?fp=${goodFingerprint}&key=${goodKey}`)).toThrowError(
      /explicit port/,
    );
  });

  it('rejects a URL with an out-of-range port', () => {
    expect(() => parseFingerprintFromUrl(`https://h:0?fp=${goodFingerprint}&key=${goodKey}`)).toThrowError(
      /URL is malformed|out of range/,
    );
  });

  it('rejects a URL with the wrong scheme', () => {
    expect(() => parseFingerprintFromUrl(`http://h:1?fp=${goodFingerprint}&key=${goodKey}`)).toThrowError(
      /https/,
    );
  });

  it('rejects malformed URLs', () => {
    expect(() => parseFingerprintFromUrl('not-a-url')).toThrowError(/malformed/);
  });

  it('rejects empty or non-string input', () => {
    expect(() => parseFingerprintFromUrl('')).toThrowError(/non-empty/);
    // Cast through unknown to exercise the runtime guard.
    expect(() => parseFingerprintFromUrl(undefined as unknown as string)).toThrowError(/non-empty/);
  });
});

describe('computeFingerprint', () => {
  it('produces a sha256:<hex> fingerprint matching the cert DER digest', () => {
    const { cert } = makeSelfSigned();
    const fp = computeFingerprint(cert);
    expect(fp).toMatch(FINGERPRINT_REGEX);

    // Re-derive independently from PEM → DER → SHA-256 to cross-check.
    const der = pemToDer(cert);
    const expected = `${FINGERPRINT_PREFIX}${createHash('sha256').update(der).digest('hex')}`;
    expect(fp).toBe(expected);
  });

  it('produces a stable fingerprint across multiple calls', () => {
    const { cert } = makeSelfSigned();
    expect(computeFingerprint(cert)).toBe(computeFingerprint(cert));
  });

  it('produces different fingerprints for different certs', () => {
    const a = makeSelfSigned();
    const b = makeSelfSigned();
    expect(computeFingerprint(a.cert)).not.toBe(computeFingerprint(b.cert));
  });

  it('rejects malformed PEM input', () => {
    expect(() => computeFingerprint('not a cert')).toThrowError(/malformed/);
  });

  it('rejects empty / non-string input', () => {
    expect(() => computeFingerprint('')).toThrowError(/non-empty/);
    expect(() => computeFingerprint(undefined as unknown as string)).toThrowError(/non-empty/);
  });
});

describe('connectWithPinnedFingerprint', () => {
  const activeServers: TlsServerType[] = [];

  afterEach(async () => {
    while (activeServers.length > 0) {
      const server = activeServers.pop();
      if (server) await new Promise<void>((r) => server.close(() => r()));
    }
  });

  async function startTlsServer(pems: SelfSignedPems): Promise<{ port: number }> {
    return new Promise((resolve) => {
      const server = createTlsServer({ cert: pems.cert, key: pems.private }, (socket) => {
        // Echo a single newline and close, just to give the socket something to do.
        socket.end('\n');
      });
      activeServers.push(server);
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address() as AddressInfo;
        resolve({ port: addr.port });
      });
    });
  }

  it('resolves with a connected socket when the fingerprint matches', async () => {
    const pems = makeSelfSigned();
    const expected = computeFingerprint(pems.cert);
    const { port } = await startTlsServer(pems);
    const socket = await connectWithPinnedFingerprint({
      host: '127.0.0.1',
      port,
      fingerprint: expected,
    });
    expect(socket.authorized).toBe(false); // expected: self-signed, no CA
    socket.destroy();
  });

  it('rejects with TlsFingerprintError when the fingerprint does not match', async () => {
    const serverPems = makeSelfSigned();
    const otherPems = makeSelfSigned();
    const wrongFingerprint = computeFingerprint(otherPems.cert);
    const { port } = await startTlsServer(serverPems);

    await expect(
      connectWithPinnedFingerprint({
        host: '127.0.0.1',
        port,
        fingerprint: wrongFingerprint,
      }),
    ).rejects.toBeInstanceOf(TlsFingerprintError);
  });

  it('rejects the promise if the expected fingerprint has the wrong format', async () => {
    await expect(
      connectWithPinnedFingerprint({
        host: '127.0.0.1',
        port: 1,
        fingerprint: 'not-a-fingerprint',
      }),
    ).rejects.toThrowError(/sha256:/);
  });

  it('rejects the promise on connection failure', async () => {
    // Port 1 on loopback should not have a listener. Use a fast timeout to keep
    // the test snappy even if the OS does something unexpected.
    await expect(
      connectWithPinnedFingerprint({
        host: '127.0.0.1',
        port: 1,
        fingerprint: `${FINGERPRINT_PREFIX}${'a'.repeat(64)}`,
        timeoutMs: 500,
      }),
    ).rejects.toBeInstanceOf(Error);
  });
});

describe('isIPv6', () => {
  it('returns true for IPv6 literals (bare and bracketed)', () => {
    expect(isIPv6('2001:db8::1')).toBe(true);
    expect(isIPv6('[2001:db8::1]')).toBe(true);
    expect(isIPv6('::1')).toBe(true);
  });
  it('returns false for IPv4 and hostnames', () => {
    expect(isIPv6('192.168.1.42')).toBe(false);
    expect(isIPv6('router.example.com')).toBe(false);
  });
});

describe('formatEndpoint / parseEndpoint', () => {
  it('leaves IPv4 authorities untouched', () => {
    expect(formatEndpoint('192.168.1.42', 9000)).toBe('192.168.1.42:9000');
  });
  it('brackets IPv6 literals', () => {
    expect(formatEndpoint('2001:db8::1', 9000)).toBe('[2001:db8::1]:9000');
  });
  it('does not double-bracket already-bracketed IPv6', () => {
    expect(formatEndpoint('[2001:db8::1]', 9000)).toBe('[2001:db8::1]:9000');
  });
  it('round-trips IPv4', () => {
    expect(parseEndpoint(formatEndpoint('10.0.0.5', 8443))).toEqual({ host: '10.0.0.5', port: 8443 });
  });
  it('round-trips IPv6, stripping the brackets', () => {
    expect(parseEndpoint(formatEndpoint('2001:db8::1', 8443))).toEqual({
      host: '2001:db8::1',
      port: 8443,
    });
  });
  it('parses a bracketed IPv6 wildcard listen address', () => {
    expect(parseEndpoint('[::]:8443')).toEqual({ host: '::', port: 8443 });
  });
  it('throws on a missing port', () => {
    expect(() => parseEndpoint('192.168.1.42')).toThrow(/port/);
  });
  it('throws on a malformed bracketed endpoint', () => {
    expect(() => parseEndpoint('[2001:db8::1]9000')).toThrow(/malformed/);
  });
});

/**
 * Convert a single-certificate PEM string to its DER bytes. Mirrors the
 * minimal logic Node uses internally so the test can cross-check
 * {@link computeFingerprint} without depending on its implementation.
 */
function pemToDer(pem: string): Buffer {
  const body = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
  return Buffer.from(body, 'base64');
}
