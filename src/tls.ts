/**
 * TLS utilities: fingerprint parsing, computation, and pinned connections.
 *
 * All ShareGrid components rely on cert fingerprint pinning instead of a
 * traditional certificate authority. The router prints its fingerprint at
 * startup; the host advertises its fingerprint via the router's host list.
 * Connecting components pin to those fingerprints — any mismatch is fatal.
 *
 * See: docs/architecture_llmrouter.md §7, docs/architecture_llmhost.md §5.2
 */

import { createHash, X509Certificate } from 'node:crypto';
import { connect as tlsConnect, type TLSSocket } from 'node:tls';

import { TlsFingerprintError, RoleKeyMissingError } from './errors.js';

/** Format prefix for SHA-256 fingerprints throughout ShareGrid. */
export const FINGERPRINT_PREFIX = 'sha256:' as const;

/** Regular expression matching the canonical fingerprint format `sha256:<64 hex chars>`. */
export const FINGERPRINT_REGEX = /^sha256:[0-9a-f]{64}$/;

/** Result of parsing a `SHAREGRID_*_URL` into its connection components. */
export interface ParsedRouterUrl {
  host: string;
  port: number;
  /** Canonical lowercase form, including the `sha256:` prefix. */
  fingerprint: string;
  /** Role-specific credential parsed from the `key=` query parameter. */
  roleKey: string;
}

/**
 * Parse a router URL of the form
 * `https://<host>:<port>?fp=sha256:<hex>&key=<base64url>`.
 *
 * Both `fp` and `key` query parameters are mandatory — there is no fallback.
 * The function normalises the fingerprint to lowercase and validates both
 * parameters before returning.
 *
 * @throws Error              if the URL is malformed, lacks an explicit port,
 *                            or has no valid `fp` query parameter.
 * @throws RoleKeyMissingError if the `key` query parameter is absent.
 */
export function parseFingerprintFromUrl(url: string): ParsedRouterUrl {
  if (typeof url !== 'string' || url.length === 0) {
    throw new Error('URL must be a non-empty string');
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`URL is malformed: ${url}`);
  }
  if (parsed.protocol !== 'https:') {
    throw new Error(`URL must use https scheme, got: ${parsed.protocol}`);
  }
  if (parsed.hostname.length === 0) {
    throw new Error('URL must include a hostname');
  }
  if (parsed.port.length === 0) {
    throw new Error('URL must include an explicit port');
  }
  const port = Number(parsed.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`URL port out of range: ${parsed.port}`);
  }

  const fpRaw = parsed.searchParams.get('fp');
  if (fpRaw === null || fpRaw.length === 0) {
    throw new Error('URL must contain an fp=sha256:<hex> query parameter');
  }
  const fingerprint = fpRaw.toLowerCase();
  if (!FINGERPRINT_REGEX.test(fingerprint)) {
    throw new Error(`fp parameter must match sha256:<64 hex chars>, got: ${fpRaw}`);
  }

  const roleKeyRaw = parsed.searchParams.get('key');
  if (roleKeyRaw === null || roleKeyRaw.length === 0) {
    throw new RoleKeyMissingError();
  }
  if (!/^[A-Za-z0-9_-]+$/.test(roleKeyRaw)) {
    throw new Error(`key parameter must be a non-empty base64url string, got: ${roleKeyRaw}`);
  }

  return { host: parsed.hostname, port, fingerprint, roleKey: roleKeyRaw };
}

/**
 * Compute the canonical SHA-256 fingerprint of a PEM-encoded X.509 certificate.
 *
 * @param certPem  PEM-encoded certificate string (must include
 *                 `-----BEGIN CERTIFICATE-----` markers).
 * @returns `sha256:<64 lowercase hex chars>`
 */
export function computeFingerprint(certPem: string): string {
  if (typeof certPem !== 'string' || certPem.length === 0) {
    throw new Error('certificate PEM must be a non-empty string');
  }
  // Construct an X509Certificate to validate the PEM and obtain DER bytes.
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(certPem);
  } catch {
    throw new Error('certificate PEM is malformed');
  }
  const digest = createHash('sha256').update(cert.raw).digest('hex');
  return `${FINGERPRINT_PREFIX}${digest}`;
}

/** Options controlling {@link connectWithPinnedFingerprint}. */
export interface PinnedConnectOptions {
  /** Hostname or IP to connect to. */
  host: string;
  /** TCP port. */
  port: number;
  /** Expected `sha256:<hex>` fingerprint. Comparison is case-insensitive. */
  fingerprint: string;
  /**
   * Optional Server Name Indication. Not required — fingerprint pinning is
   * the authoritative trust check and a self-signed cert has no CN to match.
   */
  servername?: string;
  /** Optional connection timeout in milliseconds. */
  timeoutMs?: number;
}

/**
 * Open a TLS connection and verify that the peer's certificate fingerprint
 * matches the expected value. On mismatch, the socket is destroyed and a
 * {@link TlsFingerprintError} is thrown — fail closed, no retry, no fallback.
 *
 * The pin is enforced **before** the returned promise resolves, so callers
 * may rely on a returned socket having passed the check.
 *
 * Note: `rejectUnauthorized` is set to `false` because ShareGrid does not use
 * a traditional CA — the fingerprint is the sole trust anchor. Disabling CA
 * verification is **only** safe in combination with strict fingerprint
 * pinning, which is performed in the `secureConnect` handler.
 */
export function connectWithPinnedFingerprint(opts: PinnedConnectOptions): Promise<TLSSocket> {
  const { host, port, fingerprint, servername, timeoutMs } = opts;

  const expected = fingerprint.toLowerCase();
  if (!FINGERPRINT_REGEX.test(expected)) {
    return Promise.reject(
      new Error(`fingerprint must match sha256:<64 hex chars>, got: ${fingerprint}`),
    );
  }

  return new Promise<TLSSocket>((resolve, reject) => {
    const socket = tlsConnect({
      host,
      port,
      servername,
      rejectUnauthorized: false,
    });

    let timer: NodeJS.Timeout | undefined;
    if (typeof timeoutMs === 'number' && timeoutMs > 0) {
      timer = setTimeout(() => {
        socket.destroy(new Error(`TLS connect timed out after ${timeoutMs}ms`));
      }, timeoutMs);
    }

    const cleanup = (): void => {
      if (timer !== undefined) {
        clearTimeout(timer);
        timer = undefined;
      }
      socket.removeListener('secureConnect', onSecureConnect);
      socket.removeListener('error', onError);
    };

    const onError = (err: Error): void => {
      cleanup();
      reject(err);
    };

    const onSecureConnect = (): void => {
      const peerCert = socket.getPeerCertificate(true);
      const peerFingerprint = peerCert.fingerprint256;
      if (typeof peerFingerprint !== 'string' || peerFingerprint.length === 0) {
        cleanup();
        socket.destroy();
        reject(new TlsFingerprintError('peer presented no certificate fingerprint'));
        return;
      }
      // Node returns the fingerprint as colon-separated uppercase hex.
      const normalised = `${FINGERPRINT_PREFIX}${peerFingerprint.replace(/:/g, '').toLowerCase()}`;
      if (normalised !== expected) {
        cleanup();
        socket.destroy();
        reject(
          new TlsFingerprintError(
            `peer fingerprint ${normalised} does not match expected ${expected}`,
          ),
        );
        return;
      }
      cleanup();
      resolve(socket);
    };

    socket.once('secureConnect', onSecureConnect);
    socket.once('error', onError);
  });
}
