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

/** A single chat turn carried in {@link PromptPayload.messages}. */
export interface ChatMessage {
  role: string;
  content: string;
}

/** User → Host: a chat completion request. Caller owns conversation history. */
export interface PromptPayload {
  v: ProtocolVersion;
  type: 'prompt';
  messages: ChatMessage[];
}

/** Host → User: one streamed chunk of response content. */
export interface ResponseChunk {
  v: ProtocolVersion;
  type: 'response_chunk';
  content: string;
}

/** Host → User: marker after the final chunk of a single prompt's response. */
export interface ResponseEnd {
  v: ProtocolVersion;
  type: 'response_end';
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
}

/** One entry in the host list returned to LLMUsers. */
export interface HostListEntry {
  hostId: string;
  modelName: string;
  /** `host:port` the user connects to directly. */
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
export type HostIncomingMessage = SessionOpenPayload | PromptPayload | SessionClose;

/** Any message a user may receive from a host. */
export type UserFromHostMessage =
  | SessionAck
  | SessionReject
  | ResponseChunk
  | ResponseEnd
  | SessionClose
  | SessionTimeout;

/** Any message a user may receive from a router. */
export type UserFromRouterMessage = HostListResponse;
