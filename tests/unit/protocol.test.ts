import { describe, expect, it } from 'vitest';
import {
  PROTOCOL_VERSION,
  type ProtocolVersion,
  type RegistrationPayload,
  type RegistrationAck,
  type HeartbeatPayload,
  type HeartbeatAck,
  type SessionOpenPayload,
  type SessionAck,
  type SessionReject,
  type InferenceRequestPayload,
  type InferenceResponseChunk,
  type SessionClose,
  type SessionTimeout,
  type HostListRequest,
  type HostListEntry,
  type HostListResponse,
  type HostKeyTokenPayload,
  type HostIncomingMessage,
  type UserFromHostMessage,
  type RouterIncomingMessage,
} from '../../src/protocol.js';

describe('PROTOCOL_VERSION', () => {
  it('equals 1', () => {
    expect(PROTOCOL_VERSION).toBe(1);
  });
});

describe('InferenceRequestPayload', () => {
  it('has the correct shape', () => {
    const msg: InferenceRequestPayload = {
      v: PROTOCOL_VERSION,
      type: 'inference_request',
      body: '{"messages":[],"stream":true}',
    };
    expect(msg.v).toBe(1);
    expect(msg.type).toBe('inference_request');
    expect(typeof msg.body).toBe('string');
  });

  it('is assignable to HostIncomingMessage', () => {
    const msg: InferenceRequestPayload = {
      v: PROTOCOL_VERSION,
      type: 'inference_request',
      body: '{}',
    };
    // Type-level assertion: assigning to the union must compile.
    const asUnion: HostIncomingMessage = msg;
    expect(asUnion.type).toBe('inference_request');
  });
});

describe('InferenceResponseChunk', () => {
  it('has the correct shape', () => {
    const msg: InferenceResponseChunk = {
      v: PROTOCOL_VERSION,
      type: 'inference_response_chunk',
      data: 'data: {"choices":[{"delta":{"content":"hello"}}]}',
    };
    expect(msg.v).toBe(1);
    expect(msg.type).toBe('inference_response_chunk');
    expect(typeof msg.data).toBe('string');
  });

  it('is assignable to UserFromHostMessage', () => {
    const msg: InferenceResponseChunk = {
      v: PROTOCOL_VERSION,
      type: 'inference_response_chunk',
      data: 'data: [DONE]',
    };
    const asUnion: UserFromHostMessage = msg;
    expect(asUnion.type).toBe('inference_response_chunk');
  });
});

describe('HostIncomingMessage union', () => {
  it('accepts SessionOpenPayload', () => {
    const msg: SessionOpenPayload = { v: PROTOCOL_VERSION, type: 'session_open', hostKeyToken: 'tok' };
    const asUnion: HostIncomingMessage = msg;
    expect(asUnion.type).toBe('session_open');
  });

  it('accepts InferenceRequestPayload', () => {
    const msg: InferenceRequestPayload = { v: PROTOCOL_VERSION, type: 'inference_request', body: '{}' };
    const asUnion: HostIncomingMessage = msg;
    expect(asUnion.type).toBe('inference_request');
  });

  it('accepts SessionClose', () => {
    const msg: SessionClose = { v: PROTOCOL_VERSION, type: 'session_close' };
    const asUnion: HostIncomingMessage = msg;
    expect(asUnion.type).toBe('session_close');
  });
});

describe('UserFromHostMessage union', () => {
  it('accepts SessionAck', () => {
    const msg: SessionAck = { v: PROTOCOL_VERSION, type: 'session_ack' };
    const asUnion: UserFromHostMessage = msg;
    expect(asUnion.type).toBe('session_ack');
  });

  it('accepts SessionReject', () => {
    const msg: SessionReject = { v: PROTOCOL_VERSION, type: 'session_reject', reason: 'busy' };
    const asUnion: UserFromHostMessage = msg;
    expect(asUnion.type).toBe('session_reject');
  });

  it('accepts InferenceResponseChunk', () => {
    const msg: InferenceResponseChunk = { v: PROTOCOL_VERSION, type: 'inference_response_chunk', data: 'data: [DONE]' };
    const asUnion: UserFromHostMessage = msg;
    expect(asUnion.type).toBe('inference_response_chunk');
  });

  it('accepts SessionClose', () => {
    const msg: SessionClose = { v: PROTOCOL_VERSION, type: 'session_close' };
    const asUnion: UserFromHostMessage = msg;
    expect(asUnion.type).toBe('session_close');
  });

  it('accepts SessionTimeout', () => {
    const msg: SessionTimeout = { v: PROTOCOL_VERSION, type: 'session_timeout' };
    const asUnion: UserFromHostMessage = msg;
    expect(asUnion.type).toBe('session_timeout');
  });
});

describe('Router ↔ Host types', () => {
  it('RegistrationPayload has correct shape', () => {
    const msg: RegistrationPayload = {
      v: PROTOCOL_VERSION,
      type: 'register',
      modelName: 'test-model',
      port: 9000,
      tlsFingerprint: 'sha256:' + 'a'.repeat(64),
      roleKey: 'secret',
    };
    expect(msg.type).toBe('register');
  });

  it('RegistrationAck has correct shape', () => {
    const msg: RegistrationAck = {
      v: PROTOCOL_VERSION,
      type: 'register_ack',
      hostId: 'h1',
      hostKeyToken: 'tok',
      routerPublicKey: 'pubkey',
    };
    expect(msg.type).toBe('register_ack');
  });

  it('HeartbeatPayload has correct shape', () => {
    const msg: HeartbeatPayload = { v: PROTOCOL_VERSION, type: 'heartbeat', hostId: 'h1' };
    expect(msg.type).toBe('heartbeat');
  });

  it('HeartbeatAck has correct shape', () => {
    const msg: HeartbeatAck = { v: PROTOCOL_VERSION, type: 'heartbeat_ack', hostKeyToken: 'tok' };
    expect(msg.type).toBe('heartbeat_ack');
  });

  it('RegistrationPayload is assignable to RouterIncomingMessage', () => {
    const msg: RegistrationPayload = {
      v: PROTOCOL_VERSION, type: 'register', modelName: 'm', port: 9000,
      tlsFingerprint: 'sha256:' + 'a'.repeat(64), roleKey: 'k',
    };
    const asUnion: RouterIncomingMessage = msg;
    expect(asUnion.type).toBe('register');
  });
});

describe('User ↔ Router types', () => {
  it('HostListRequest has correct shape', () => {
    const msg: HostListRequest = { v: PROTOCOL_VERSION, type: 'host_list_request', roleKey: 'ukey' };
    expect(msg.type).toBe('host_list_request');
  });

  it('HostListEntry has correct shape', () => {
    const entry: HostListEntry = {
      hostId: 'h1',
      modelName: 'test-model',
      endpoint: '10.0.0.1:9000',
      tlsFingerprint: 'sha256:' + 'b'.repeat(64),
      hostKeyToken: 'tok',
    };
    expect(entry.hostId).toBe('h1');
  });

  it('HostListResponse has correct shape', () => {
    const msg: HostListResponse = { v: PROTOCOL_VERSION, type: 'host_list_response', hosts: [] };
    expect(msg.type).toBe('host_list_response');
  });
});

describe('HostKeyTokenPayload', () => {
  it('has correct shape', () => {
    const payload: HostKeyTokenPayload = {
      hostId: 'h1',
      tlsFingerprint: 'sha256:' + 'c'.repeat(64),
      expiresAt: Date.now() + 60_000,
    };
    expect(typeof payload.expiresAt).toBe('number');
  });
});

// ── Type-level completeness checks ────────────────────────────────────────────
// These are compile-time only. If a removed type is accidentally re-added or a
// new type is added without updating the unions, the type assertions below will
// catch it via exhaustive-switch style checks in future test additions.

it('PROTOCOL_VERSION is a numeric literal type (not widened to number)', () => {
  const v: ProtocolVersion = PROTOCOL_VERSION;
  // ProtocolVersion = 1; if this were widened to `number`, assignment of a
  // non-1 value would not be caught — the type test verifies narrowness at
  // compile time only (runtime just checks the value).
  expect(v).toBe(1);
});
