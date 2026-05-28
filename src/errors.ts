/**
 * Typed error classes shared across all ShareGrid components.
 *
 * Each error carries a `readonly code` literal so callers can branch by code
 * (`if (err instanceof HostBusyError)`) without parsing error messages. See
 * `docs/implementation_guidelines.md` §5 (Error Handling).
 */

/** Discriminating code for {@link HostBusyError}. */
export const HOST_BUSY = 'HOST_BUSY' as const;
/** Discriminating code for {@link InvalidTokenError}. */
export const INVALID_TOKEN = 'INVALID_TOKEN' as const;
/** Discriminating code for {@link NotRegisteredError}. */
export const NOT_REGISTERED = 'NOT_REGISTERED' as const;
/** Discriminating code for {@link SlotEraseError}. */
export const SLOT_ERASE_FAILED = 'SLOT_ERASE_FAILED' as const;
/** Discriminating code for {@link ProtocolVersionError}. */
export const PROTOCOL_VERSION_MISMATCH = 'PROTOCOL_VERSION_MISMATCH' as const;
/** Discriminating code for {@link TlsFingerprintError}. */
export const TLS_FINGERPRINT_MISMATCH = 'TLS_FINGERPRINT_MISMATCH' as const;
/** Discriminating code for {@link RegistrationRejectedError}. */
export const REGISTRATION_REJECTED = 'REGISTRATION_REJECTED' as const;
/** Discriminating code for {@link HostNotFoundError}. */
export const HOST_NOT_FOUND = 'HOST_NOT_FOUND' as const;
/** Discriminating code for {@link RouterStartupError}. */
export const ROUTER_STARTUP_FAILED = 'ROUTER_STARTUP_FAILED' as const;

/**
 * The host's single session slot is already occupied.
 *
 * Raised by the LLMHost session manager when a `session_open` arrives while a
 * session is already active; surfaced to the LLMUser as a recoverable error
 * (offer to re-select another host).
 */
export class HostBusyError extends Error {
  readonly code = HOST_BUSY;
  constructor(message = 'host session slot is occupied') {
    super(message);
    this.name = 'HostBusyError';
  }
}

/**
 * The presented host key token is invalid.
 *
 * Raised when Ed25519 signature verification fails, the signed payload does
 * not match the host, or the token is outside the freshness window. Always
 * fail-closed: no partial matches.
 */
export class InvalidTokenError extends Error {
  readonly code = INVALID_TOKEN;
  constructor(message = 'host key token is invalid') {
    super(message);
    this.name = 'InvalidTokenError';
  }
}

/**
 * The host has not yet (or no longer) confirmed registration with the router.
 *
 * Raised when a `session_open` arrives before the host has received its first
 * `register_ack`, or after the router connection has been lost and the
 * session manager has been told to stop accepting new sessions.
 */
export class NotRegisteredError extends Error {
  readonly code = NOT_REGISTERED;
  constructor(message = 'host is not registered with a router') {
    super(message);
    this.name = 'NotRegisteredError';
  }
}

/**
 * The llama.cpp slot wipe (`DELETE /slots/0`) failed after a session ended.
 *
 * Fatal at the LLMHost: triggers a non-zero process exit so Docker can
 * restart the container with a clean state. See
 * `architecture_llmhost.md` §5.4.
 */
export class SlotEraseError extends Error {
  readonly code = SLOT_ERASE_FAILED;
  constructor(message = 'llama.cpp slot erase failed') {
    super(message);
    this.name = 'SlotEraseError';
  }
}

/**
 * A received wire message had an unexpected `v` field.
 *
 * Receivers must reject any message whose `v` does not match
 * `PROTOCOL_VERSION` rather than misinterpreting future formats. See
 * `implementation_guidelines.md` §6.
 */
export class ProtocolVersionError extends Error {
  readonly code = PROTOCOL_VERSION_MISMATCH;
  constructor(message = 'unsupported protocol version') {
    super(message);
    this.name = 'ProtocolVersionError';
  }
}

/**
 * The remote TLS certificate's SHA-256 fingerprint did not match the pinned value.
 *
 * Raised by `connectWithPinnedFingerprint` before any payload is sent. Always
 * fail-closed — no retry, no fallback.
 */
export class TlsFingerprintError extends Error {
  readonly code = TLS_FINGERPRINT_MISMATCH;
  constructor(message = 'TLS certificate fingerprint mismatch') {
    super(message);
    this.name = 'TlsFingerprintError';
  }
}

/**
 * The router refused to accept a host registration.
 *
 * Raised on malformed registration payloads, invalid field values, or any
 * router-side precondition failure.
 */
export class RegistrationRejectedError extends Error {
  readonly code = REGISTRATION_REJECTED;
  constructor(message = 'host registration rejected by router') {
    super(message);
    this.name = 'RegistrationRejectedError';
  }
}

/**
 * The router's host registry does not contain the referenced host.
 *
 * Raised when a heartbeat arrives for a host that has been evicted, or any
 * other lookup that fails to match.
 */
export class HostNotFoundError extends Error {
  readonly code = HOST_NOT_FOUND;
  constructor(message = 'host not found in registry') {
    super(message);
    this.name = 'HostNotFoundError';
  }
}

/**
 * The router failed to complete its startup sequence.
 *
 * Raised when the TLS cert store cannot be initialised, the listen port is
 * unavailable, or any other unrecoverable startup precondition fails. Fatal
 * at the router: triggers a non-zero process exit.
 */
export class RouterStartupError extends Error {
  readonly code = ROUTER_STARTUP_FAILED;
  constructor(message = 'router startup failed') {
    super(message);
    this.name = 'RouterStartupError';
  }
}

/** Union of all error codes exported by this module. */
export type ShareGridErrorCode =
  | typeof HOST_BUSY
  | typeof INVALID_TOKEN
  | typeof NOT_REGISTERED
  | typeof SLOT_ERASE_FAILED
  | typeof PROTOCOL_VERSION_MISMATCH
  | typeof TLS_FINGERPRINT_MISMATCH
  | typeof REGISTRATION_REJECTED
  | typeof HOST_NOT_FOUND
  | typeof ROUTER_STARTUP_FAILED;
