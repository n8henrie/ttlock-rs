//! The single error type shared by every operation in this crate.

use thiserror::Error;

use crate::packet::{COMM_CHECK_USER_TIME, COMM_FUNCTION_LOCK, COMM_UNLOCK};

/// Anything that can go wrong while parsing, building, or driving a `TTLock`
/// exchange.
///
/// Callers mostly care about three groups:
///
/// - **Transport-recoverable** — [`Self::CrcMismatch`] alone. The lock's reply
///   arrived corrupted, which says nothing about whether the command was
///   understood. Re-sending the same frame is safe and usually works, because
///   operations validate the CRC before advancing any state.
/// - **Rejected by the lock** — [`Self::CommandFailed`] and
///   [`Self::UnexpectedCommand`]. The lock decrypted the request and refused
///   it. Retrying identical bytes will fail identically; the credentials or the
///   protocol version need fixing.
/// - **Malformed input** — everything else. A bug, a truncated frame, or bad
///   lock data.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TtlockError {
    /// Reading or writing a file failed (for example `lockData.json`).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// `lockData.json` could not be parsed or serialized.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// A hex string (typically an AES key) contained non-hex characters.
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    /// A base64 credential from the Sciener database was not valid base64.
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Decoded credential bytes were not valid UTF-8, so they cannot be the
    /// comma-separated digit list the format requires.
    #[error("UTF-8 decode error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    /// `TTLock` uses AES-128, so keys are always 16 bytes. Carries the length
    /// actually supplied.
    ///
    /// Raised only by [`AesKey::from_hex`](crate::credential::AesKey::from_hex),
    /// which is the single door into the type. Past that point the length is a
    /// property of the type and cannot be wrong.
    #[error("AES key must be exactly 16 bytes; got {0} bytes")]
    InvalidAesKeyLength(usize),

    /// A value offered as an unlock key cannot be one.
    ///
    /// Deliberately does not echo the offending value: it is a credential, and
    /// this message reaches logs and Home Assistant's UI. Zero is called out by
    /// name because it is what an empty or unfilled field collapses to, and
    /// because the lock refuses it in a way that looks like a protocol fault
    /// rather than a bad credential.
    #[error(
        "invalid unlock key: expected a whole number from 1 to 4294967295 \
         (0 is what an empty field becomes, and is never a valid key)"
    )]
    InvalidUnlockKey,

    /// AES-CBC decryption failed: the ciphertext length was not a multiple of
    /// the block size, or PKCS#7 padding was invalid. Usually the wrong AES key.
    #[error("AES decryption failed")]
    AesDecrypt,

    /// The frame ended before the 13-byte envelope header was complete.
    #[error("packet is too short")]
    PacketTooShort,

    /// The frame did not begin with the `7f5a` magic that starts every `TTLock`
    /// packet.
    #[error("packet does not start with 7f5a")]
    BadHeader,

    /// The envelope's length field claimed more payload than the buffer holds.
    #[error("packet length field exceeds buffer length")]
    BadLength,

    /// The frame's trailing CRC did not match the CRC computed over its body.
    ///
    /// The one error worth retrying: re-send the same frame and read the reply
    /// again. See the type-level docs.
    #[error("packet CRC mismatch: observed 0x{observed:02x}, computed 0x{computed:02x}")]
    CrcMismatch {
        /// The CRC byte carried by the frame.
        observed: u8,
        /// The CRC computed over the frame's own bytes.
        computed: u8,
    },

    /// A required field was absent from `lockData.json`. Carries the field's
    /// dotted path, e.g. `private_data.aes_key`.
    #[error("missing required lock data field: {0}")]
    MissingLockData(&'static str),

    /// A frame arrived echoing a command other than the one being awaited.
    ///
    /// Usually an *unsolicited* frame rather than a desynchronized exchange:
    /// the lock pushes notifications on the same characteristic it answers on,
    /// so one can land inside a command's response window. Every lock-to-phone
    /// frame carries [`COMM_RESPONSE`](crate::packet::COMM_RESPONSE) at the
    /// envelope level, so only the decrypted plaintext says what a frame is
    /// actually about — which means the transport cannot filter these and the
    /// operation must.
    ///
    /// Like [`Self::CrcMismatch`], this is raised *before* the operation
    /// advances any state: the command byte is checked first. Discarding the
    /// frame and reading the next one therefore resumes the exchange. See
    /// [`Self::is_stale_frame`].
    #[error("unexpected response command: expected 0x{expected:02x}, got 0x{actual:02x}")]
    UnexpectedCommand {
        /// Command byte the operation was waiting for.
        expected: u8,
        /// Command byte the lock actually replied with.
        actual: u8,
    },

    /// A command the lock decrypted and then rejected.
    ///
    /// The command byte is carried because lock/unlock is a two-step exchange
    /// whose steps fail for different reasons: a rejected check-user-time
    /// (`0x55`) points at the AES key or protocol version, a rejected actuation
    /// (`0x58`/`0x47`) at the unlock key. [`rejection_hint`] turns that into
    /// words, so every consumer says the same useful thing instead of listing
    /// every credential it can think of.
    #[error(
        "command 0x{command:02x} failed with response byte 0x{response:02x} — {}",
        rejection_hint(*command)
    )]
    CommandFailed {
        /// The command byte that was rejected.
        command: u8,
        /// The lock's response byte; `1` means success, anything else failure.
        response: u8,
    },

    /// A response decrypted cleanly but was shorter than the field being read.
    /// Carries a description of what was being extracted.
    #[error("not enough response data for {0}")]
    ShortResponse(&'static str),

    /// A decoded credential did not fit in a `u32`, so it is not a valid
    /// `TTLock` admin passcode or unlock key.
    #[error("credential value does not fit in u32")]
    CredentialOverflow,

    /// A condition with no more specific variant. Carries a human-readable
    /// description.
    #[error("{0}")]
    Message(String),
}

/// What a rejection of `command` most likely implicates.
///
/// Actuation is a two-step exchange, and *which* step the lock refused narrows
/// the cause sharply — so sharply that naming every credential would be worse
/// than saying nothing. A rejected actuation in particular proves the AES key
/// and the protocol version are correct, because the handshake that precedes it
/// could not otherwise have succeeded.
#[must_use]
pub const fn rejection_hint(command: u8) -> &'static str {
    match command {
        COMM_CHECK_USER_TIME => {
            "the handshake was refused, which points at the AES key or the protocol version"
        }
        COMM_FUNCTION_LOCK | COMM_UNLOCK => {
            "the handshake succeeded, so the AES key and protocol version are right; \
             this points at the unlock key"
        }
        _ => "the lock refused the command",
    }
}

impl TtlockError {
    /// Whether re-sending the same frame could plausibly succeed.
    ///
    /// True only for [`Self::CrcMismatch`]. That is not a shortcut: operations
    /// verify the CRC before advancing any of their own state, so a corrupted
    /// reply leaves the exchange exactly where it was and a re-send resumes it.
    /// Every other variant means the lock decrypted the command and rejected
    /// it — identical bytes get rejected identically — or indicates a bug, and
    /// retrying only drains the lock's batteries.
    ///
    /// Transport failures (a dropped connection, a timeout) are not represented
    /// here at all; they belong to whatever moves the bytes, and are retryable
    /// on their own terms.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::CrcMismatch { .. })
    }

    /// Whether this frame should be discarded and the *next* one awaited,
    /// without re-sending anything.
    ///
    /// True only for [`Self::UnexpectedCommand`]. The lock pushes unsolicited
    /// frames on the same characteristic it replies on, so one can arrive inside
    /// a command's response window. Consuming it as the response is a real
    /// hazard: parsers that did not check the echoed opcode would read a log
    /// push as a status reply — for a manual key turn that yields `LOCKED`
    /// while the door stands open — and would also leave the genuine reply in
    /// the queue, desynchronizing every later exchange by one frame.
    ///
    /// Distinct from [`Self::is_retryable`], and the difference matters: a CRC
    /// failure means re-send the same frame, whereas this means send nothing
    /// and keep reading. A caller must also keep the *original* deadline rather
    /// than restarting it, or a chatty lock postpones a timeout indefinitely,
    /// and must bound how many it will skip so a genuine desynchronization
    /// still surfaces instead of turning into a silent timeout.
    #[must_use]
    pub const fn is_stale_frame(&self) -> bool {
        matches!(self, Self::UnexpectedCommand { .. })
    }
}

/// [`Result`](std::result::Result) specialized to [`TtlockError`].
pub type Result<T> = std::result::Result<T, TtlockError>;
