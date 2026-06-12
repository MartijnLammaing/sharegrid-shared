/**
 * Wire protocol — all ShareGrid component-to-component communication.
 *
 * Framing: newline-delimited JSON over TLS. Each message is a single-line
 * JSON object terminated by `\n`. JSON values must not contain literal
 * newlines (use `\n` escape sequences in string values if needed).
 *
 * See: docs/implementation_guidelines.md §6, §6.1, §6.2, §6.3
 */

/** Current protocol version. Bumped only on breaking wire changes. */
export const PROTOCOL_VERSION = 1 as const;

/** Type alias for the version field on every message. */
export type ProtocolVersion = typeof PROTOCOL_VERSION;

// ─────────────────────────────────────────────────────────────────────────────
// Router ↔ Host
// ─────────────────────────────────────────────────────────────────────────────

/** Host → Router: initial registration after TLS connect. */
export interface RegistrationPayload {
  v: ProtocolVersion;
  type: 'register';
  modelName: string;
  port: number;
  tlsFingerprint: string;
  /**
   * The host's advertised address, matching the router's network mode: an IPv4
   * literal in `lan` mode, or an IPv6 literal (bare, no brackets) in `internet`
   * mode. The router brackets it into the registry `endpoint` via
   * `formatEndpoint`. See docs/architecture_overview.md §9.
   */
  listenHost: string;
  /** Role credential parsed from the host registration URL (`key=` param). */
  roleKey: string;
  /**
   * Externally-reachable IP address of the host (IPv6 preferred, IPv4 fallback).
   * The router uses this to build the endpoint returned to users, rather than
   * relying on sock.remoteAddress which may be a Docker bridge IP when
   * co-located with the router.
   */
  listenHost: string;
}

/** Router → Host: response to a successful registration. */
export interface RegistrationAck {
  v: ProtocolVersion;
  type: 'register_ack';
  hostId: string;
  hostKeyToken: string;
  routerPublicKey: string;
}

/** Host → Router: keep-alive ping; carries the issued host id. */
export interface HeartbeatPayload {
  v: ProtocolVersion;
  type: 'heartbeat';
  hostId: string;
}

/** Router → Host: response to a heartbeat; carries a freshly issued token. */
export interface HeartbeatAck {
  v: ProtocolVersion;
  type: 'heartbeat_ack';
  hostKeyToken: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// User ↔ Host (session)
// ─────────────────────────────────────────────────────────────────────────────

/** User → Host: first message after TLS connect; presents the host key token. */
export interface SessionOpenPayload {
  v: ProtocolVersion;
  type: 'session_open';
  hostKeyToken: string;
}

/** Host → User: session accepted; the slot is now occupied. */
export interface SessionAck {
  v: ProtocolVersion;
  type: 'session_ack';
}

/** Host → User: session refused; gives a specific reason. */
export interface SessionReject {
  v: ProtocolVersion;
  type: 'session_reject';
  reason: 'busy' | 'invalid_token' | 'not_registered';
}

/**
 * User → Host: carries the full OpenAI `/v1/chat/completions` request body.
 *
 * The `body` field is the JSON-serialised OpenAI request (messages, tools,
 * tool_choice, stream flag, etc.). The host forwards it verbatim to llama.cpp
 * and streams raw SSE lines back via `InferenceResponseChunk`.
 */
export interface InferenceRequestPayload {
  v: ProtocolVersion;
  type: 'inference_request';
  body: string;
}

/**
 * Host → User: one raw SSE line from llama.cpp.
 *
 * Examples: `"data: {\"choices\":[...]}"` or `"data: [DONE]"`.
 * The user adapter forwards these lines verbatim to the HTTP client (OpenCode).
 * The `data: [DONE]` line signals the end of the inference stream.
 */
export interface InferenceResponseChunk {
  v: ProtocolVersion;
  type: 'inference_response_chunk';
  data: string;
}

/** Either party: request graceful session shutdown. */
export interface SessionClose {
  v: ProtocolVersion;
  type: 'session_close';
}

/** Host → User: idle timeout reached; the host will close the connection. */
export interface SessionTimeout {
  v: ProtocolVersion;
  type: 'session_timeout';
}

// ─────────────────────────────────────────────────────────────────────────────
// User ↔ Router (host list)
// ─────────────────────────────────────────────────────────────────────────────

/** User → Router: first and only message after TLS connect. */
export interface HostListRequest {
  v: ProtocolVersion;
  type: 'host_list_request';
  /** Role credential parsed from the user access URL (`key=` param). */
  roleKey: string;
}

/** One entry in the host list returned to LLMUsers. */
export interface HostListEntry {
  hostId: string;
  modelName: string;
  /** `host:port` the user connects to directly; an IPv6 host is bracketed (`[2001:db8::1]:9000`). Split with `parseEndpoint`. */
  endpoint: string;
  /** `sha256:<hex>`; pinned by the user before opening a session. */
  tlsFingerprint: string;
  /** Opaque session credential; presented verbatim to the host. */
  hostKeyToken: string;
}

/** Router → User: list of currently active hosts; router closes the connection after sending. */
export interface HostListResponse {
  v: ProtocolVersion;
  type: 'host_list_response';
  hosts: HostListEntry[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Host key token payload (signed by router, presented by user to host)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The signed payload inside a host key token. The wire format is:
 *
 *   base64url(JSON.stringify(payload)) + "." + base64url(ed25519_signature)
 *
 * The Ed25519 signature is computed over the **base64url-encoded payload
 * string**, not over the raw JSON bytes. See encode/decode helpers in
 * `./crypto` (token module).
 */
export interface HostKeyTokenPayload {
  hostId: string;
  /** `sha256:<hex>` of the host's TLS cert. */
  tlsFingerprint: string;
  /** Unix epoch milliseconds. */
  expiresAt: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Discriminated unions for incoming-message handling
// ─────────────────────────────────────────────────────────────────────────────

/** Any message a router may receive from any peer. */
export type RouterIncomingMessage = RegistrationPayload | HeartbeatPayload | HostListRequest;

/** Any message a host may receive from a connected user. */
export type HostIncomingMessage = SessionOpenPayload | InferenceRequestPayload | SessionClose;

/** Any message a user may receive from a host. */
export type UserFromHostMessage =
  | SessionAck
  | SessionReject
  | InferenceResponseChunk
  | SessionClose
  | SessionTimeout;

/** Any message a user may receive from a router. */
export type UserFromRouterMessage = HostListResponse;
