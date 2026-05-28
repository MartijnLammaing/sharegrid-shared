import { describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';

import {
  base64UrlDecode,
  base64UrlEncode,
  decodeHostKeyToken,
  encodeHostKeyToken,
  generateEd25519KeyPair,
  signEd25519,
  verifyEd25519,
} from '../../src/crypto.js';
import type { HostKeyTokenPayload } from '../../src/protocol.js';

const payload = Buffer.from('the quick brown fox jumps over the lazy dog', 'utf8');

describe('signEd25519 / verifyEd25519', () => {
  it('sign/verify round-trip succeeds', () => {
    const { privateKey, publicKey } = generateEd25519KeyPair();
    const sig = signEd25519(privateKey, payload);
    expect(sig).toBeInstanceOf(Buffer);
    expect(sig.length).toBe(64);
    expect(verifyEd25519(publicKey, payload, sig)).toBe(true);
  });

  it('verify rejects a tampered payload', () => {
    const { privateKey, publicKey } = generateEd25519KeyPair();
    const sig = signEd25519(privateKey, payload);
    const tampered = Buffer.from(payload);
    tampered.writeUInt8(tampered.readUInt8(0) ^ 0x01, 0);
    expect(verifyEd25519(publicKey, tampered, sig)).toBe(false);
  });

  it('verify rejects when the public key does not match the signer', () => {
    const signer = generateEd25519KeyPair();
    const other = generateEd25519KeyPair();
    const sig = signEd25519(signer.privateKey, payload);
    expect(verifyEd25519(other.publicKey, payload, sig)).toBe(false);
  });

  it('verify rejects a malformed (wrong-length) signature', () => {
    const { publicKey } = generateEd25519KeyPair();
    const bogus = Buffer.alloc(63, 0xff); // Ed25519 signatures are exactly 64 bytes
    expect(verifyEd25519(publicKey, payload, bogus)).toBe(false);
  });

  it('verify rejects a tampered signature of the correct length', () => {
    const { privateKey, publicKey } = generateEd25519KeyPair();
    const sig = signEd25519(privateKey, payload);
    const tampered = Buffer.from(sig);
    tampered.writeUInt8(tampered.readUInt8(0) ^ 0xff, 0);
    expect(verifyEd25519(publicKey, payload, tampered)).toBe(false);
  });

  it('sign rejects a non-private key', () => {
    const { publicKey } = generateEd25519KeyPair();
    expect(() => signEd25519(publicKey, payload)).toThrowError(/private/);
  });

  it('verify with a non-public key returns false (fails closed)', () => {
    const { privateKey } = generateEd25519KeyPair();
    const sig = Buffer.alloc(64, 0x00);
    expect(verifyEd25519(privateKey, payload, sig)).toBe(false);
  });

  it('accepts PEM-encoded keys as input', () => {
    const { privateKey, publicKey } = generateEd25519KeyPair();
    const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const sig = signEd25519(privatePem, payload);
    expect(verifyEd25519(publicPem, payload, sig)).toBe(true);
  });

  it('round-trips correctly when the message is the empty byte string', () => {
    const { privateKey, publicKey } = generateEd25519KeyPair();
    const empty = new Uint8Array(0);
    const sig = signEd25519(privateKey, empty);
    expect(verifyEd25519(publicKey, empty, sig)).toBe(true);
  });
});

describe('base64UrlEncode / base64UrlDecode', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = Buffer.from([0x00, 0xff, 0x7f, 0x80, 0x41, 0x42, 0x43]);
    const text = base64UrlEncode(bytes);
    expect(text).not.toMatch(/[+/=]/); // base64url: no +, /, or padding
    expect(base64UrlDecode(text).equals(bytes)).toBe(true);
  });

  it('rejects strings containing invalid characters', () => {
    expect(() => base64UrlDecode('abc!def')).toThrowError(/invalid base64url/);
  });

  it('accepts the empty string as valid (empty bytes)', () => {
    expect(base64UrlDecode('').length).toBe(0);
  });
});

describe('encodeHostKeyToken / decodeHostKeyToken', () => {
  const examplePayload: HostKeyTokenPayload = {
    hostId: 'host_abc123',
    tlsFingerprint: 'sha256:' + 'a'.repeat(64),
    expiresAt: 1716148800000,
  };

  it('round-trips encode → decode preserving payload and signature', () => {
    const { privateKey, publicKey } = generateEd25519KeyPair();
    const payloadJson = JSON.stringify(examplePayload);
    const payloadB64 = base64UrlEncode(Buffer.from(payloadJson, 'utf8'));
    const signature = signEd25519(privateKey, Buffer.from(payloadB64, 'utf8'));

    const token = encodeHostKeyToken(examplePayload, signature);
    const decoded = decodeHostKeyToken(token);

    expect(decoded.payload).toEqual(examplePayload);
    expect(decoded.signature.equals(signature)).toBe(true);
    expect(decoded.payloadB64).toBe(payloadB64);

    // Signature is over the base64url-encoded payload string — verify exactly that.
    expect(verifyEd25519(publicKey, Buffer.from(decoded.payloadB64, 'utf8'), decoded.signature)).toBe(
      true,
    );
  });

  it('rejects tokens without exactly one "."', () => {
    expect(() => decodeHostKeyToken('no-dot-here')).toThrowError(/exactly one/);
    expect(() => decodeHostKeyToken('a.b.c')).toThrowError(/exactly one/);
  });

  it('rejects malformed base64url in either part', () => {
    expect(() => decodeHostKeyToken('!!.bb')).toThrowError(/malformed base64url/);
    expect(() => decodeHostKeyToken('aa.!!')).toThrowError(/malformed base64url/);
  });

  it('rejects payloads that are not valid JSON', () => {
    const garbageB64 = base64UrlEncode(Buffer.from('not-json', 'utf8'));
    const sigB64 = base64UrlEncode(Buffer.alloc(64));
    expect(() => decodeHostKeyToken(`${garbageB64}.${sigB64}`)).toThrowError(/valid JSON/);
  });

  it('rejects payloads missing required fields', () => {
    const badPayload = JSON.stringify({ hostId: 'x' });
    const payloadB64 = base64UrlEncode(Buffer.from(badPayload, 'utf8'));
    const sigB64 = base64UrlEncode(Buffer.alloc(64));
    expect(() => decodeHostKeyToken(`${payloadB64}.${sigB64}`)).toThrowError(/tlsFingerprint/);
  });

  it('rejects payloads with the wrong fingerprint format', () => {
    const badPayload = JSON.stringify({
      hostId: 'x',
      tlsFingerprint: 'sha1:abc',
      expiresAt: 1,
    });
    const payloadB64 = base64UrlEncode(Buffer.from(badPayload, 'utf8'));
    const sigB64 = base64UrlEncode(Buffer.alloc(64));
    expect(() => decodeHostKeyToken(`${payloadB64}.${sigB64}`)).toThrowError(/sha256:/);
  });

  it('rejects non-string input', () => {
    // Cast through unknown to bypass the parameter type at the call site.
    expect(() => decodeHostKeyToken(undefined as unknown as string)).toThrowError(/non-empty/);
    expect(() => decodeHostKeyToken('')).toThrowError(/non-empty/);
  });
});

describe('generateEd25519KeyPair', () => {
  it('returns a private and public KeyObject pair', () => {
    const { privateKey, publicKey } = generateEd25519KeyPair();
    expect(privateKey.type).toBe('private');
    expect(publicKey.type).toBe('public');
    expect(privateKey.asymmetricKeyType).toBe('ed25519');
    expect(publicKey.asymmetricKeyType).toBe('ed25519');
  });

  it('returns a different keypair each invocation', () => {
    const a = generateKeyPairSync('ed25519');
    const b = generateKeyPairSync('ed25519');
    const aPub = a.publicKey.export({ type: 'spki', format: 'pem' });
    const bPub = b.publicKey.export({ type: 'spki', format: 'pem' });
    expect(aPub).not.toBe(bPub);
  });
});
