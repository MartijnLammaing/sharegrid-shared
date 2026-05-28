/**
 * Cryptographic primitives for ShareGrid.
 *
 * Backed entirely by Node.js's built-in `crypto` module — no third-party
 * crypto implementations are introduced.
 *
 * See: docs/implementation_guidelines.md §13 (Dependency Policy)
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
  type KeyObject,
  type KeyPairKeyObjectResult,
} from 'node:crypto';

import type { HostKeyTokenPayload } from './protocol.js';

/** Accepted input forms for keys: native KeyObject or PEM string. */
export type KeyInput = KeyObject | string;

/**
 * Generate a fresh Ed25519 keypair.
 *
 * Both keys are held in memory as Node.js `KeyObject`s; callers may serialise
 * to PEM for transport via the standard `.export({ type, format })` method.
 */
export function generateEd25519KeyPair(): KeyPairKeyObjectResult {
  return generateKeyPairSync('ed25519');
}

/**
 * Sign an arbitrary byte string with an Ed25519 private key.
 *
 * Ed25519 in Node.js is invoked by passing `null` as the digest algorithm,
 * which is the documented convention for EdDSA.
 *
 * @param privateKey  Ed25519 private key (KeyObject or PEM string).
 * @param payload     Bytes to sign.
 * @returns Detached signature, exactly 64 bytes.
 */
export function signEd25519(privateKey: KeyInput, payload: Uint8Array): Buffer {
  const key = toPrivateKeyObject(privateKey);
  return nodeSign(null, payload, key);
}

/**
 * Verify an Ed25519 detached signature.
 *
 * Returns `true` only when the signature is valid for the given payload and
 * public key. Returns `false` (never throws) for any verification failure —
 * tampered payload, wrong public key, malformed signature, or wrong-length
 * inputs. Callers must treat the boolean as authoritative.
 *
 * @param publicKey  Ed25519 public key (KeyObject or PEM string).
 * @param payload    Bytes that were signed.
 * @param signature  64-byte detached Ed25519 signature.
 */
export function verifyEd25519(
  publicKey: KeyInput,
  payload: Uint8Array,
  signature: Uint8Array,
): boolean {
  let key: KeyObject;
  try {
    key = toPublicKeyObject(publicKey);
  } catch {
    return false;
  }
  try {
    return nodeVerify(null, payload, key, signature);
  } catch {
    // Node throws on malformed/wrong-length signatures; treat as a fail-closed
    // verification result rather than propagating to the caller.
    return false;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Host key token wire format
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Encoded host key token: `base64url(JSON.stringify(payload)) + "." + base64url(signature)`.
 *
 * The signature is computed over the base64url-encoded payload **string**
 * (the first part), not over the raw JSON bytes. This makes the signed
 * material stable across JSON serialisers and avoids canonicalisation
 * concerns at verification time.
 *
 * See: docs/architecture_llmrouter.md §4.2,
 *      docs/implementation_guidelines.md §6.3
 */
export function encodeHostKeyToken(payload: HostKeyTokenPayload, signature: Uint8Array): string {
  const payloadJson = JSON.stringify(payload);
  const payloadB64 = base64UrlEncode(Buffer.from(payloadJson, 'utf8'));
  const signatureB64 = base64UrlEncode(signature);
  return `${payloadB64}.${signatureB64}`;
}

/** Decoded form of a host key token. {@link payloadB64} is the signed material. */
export interface DecodedHostKeyToken {
  /** The base64url-encoded payload string — verify the signature against THIS. */
  payloadB64: string;
  payload: HostKeyTokenPayload;
  signature: Buffer;
}

/**
 * Decode a host key token. Throws on malformed input.
 *
 * Validates structure (exactly one `.`, both parts base64url-decodable,
 * payload parses as JSON with the required fields) but does NOT verify the
 * signature — callers must invoke {@link verifyEd25519} with
 * {@link DecodedHostKeyToken.payloadB64} as the signed payload.
 */
export function decodeHostKeyToken(token: string): DecodedHostKeyToken {
  if (typeof token !== 'string' || token.length === 0) {
    throw new Error('host key token must be a non-empty string');
  }
  const parts = token.split('.');
  if (parts.length !== 2) {
    throw new Error('host key token must contain exactly one "."');
  }
  const [payloadB64, signatureB64] = parts as [string, string];

  let payloadBytes: Buffer;
  let signature: Buffer;
  try {
    payloadBytes = base64UrlDecode(payloadB64);
    signature = base64UrlDecode(signatureB64);
  } catch {
    throw new Error('host key token contains malformed base64url');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(payloadBytes.toString('utf8'));
  } catch {
    throw new Error('host key token payload is not valid JSON');
  }
  const payload = assertHostKeyTokenPayload(parsed);

  return { payloadB64, payload, signature };
}

function assertHostKeyTokenPayload(value: unknown): HostKeyTokenPayload {
  if (typeof value !== 'object' || value === null) {
    throw new Error('host key token payload is not an object');
  }
  const record = value as Record<string, unknown>;
  const { hostId, tlsFingerprint, expiresAt } = record;
  if (typeof hostId !== 'string' || hostId.length === 0) {
    throw new Error('host key token payload: hostId must be a non-empty string');
  }
  if (typeof tlsFingerprint !== 'string' || !tlsFingerprint.startsWith('sha256:')) {
    throw new Error('host key token payload: tlsFingerprint must be a sha256:... string');
  }
  if (typeof expiresAt !== 'number' || !Number.isFinite(expiresAt) || expiresAt <= 0) {
    throw new Error('host key token payload: expiresAt must be a positive number');
  }
  return { hostId, tlsFingerprint, expiresAt };
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

function toPrivateKeyObject(input: KeyInput): KeyObject {
  if (typeof input === 'string') {
    return createPrivateKey(input);
  }
  if (input.type !== 'private') {
    throw new Error('expected a private key, received a key of type: ' + input.type);
  }
  return input;
}

function toPublicKeyObject(input: KeyInput): KeyObject {
  if (typeof input === 'string') {
    return createPublicKey(input);
  }
  // Node accepts a private key wherever a public key is expected (it derives
  // the public half), but we keep the type check strict: callers should pass
  // the public key explicitly.
  if (input.type !== 'public') {
    throw new Error('expected a public key, received a key of type: ' + input.type);
  }
  return input;
}

/** RFC 4648 §5 base64url encoding (no padding). */
export function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/** RFC 4648 §5 base64url decoding. Throws on invalid input. */
export function base64UrlDecode(text: string): Buffer {
  if (typeof text !== 'string') {
    throw new Error('base64url input must be a string');
  }
  // Node's 'base64url' decoder silently accepts some garbage; tighten with a
  // regex so callers get a deterministic error on malformed input.
  if (!/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new Error('invalid base64url characters');
  }
  return Buffer.from(text, 'base64url');
}
