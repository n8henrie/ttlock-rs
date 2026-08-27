//! The on-wire packet envelope: building, parsing, and the command payloads.
//!
//! Every exchange is a frame shaped
//! `7f5a <version header> <command> <encrypt> <len> <AES payload> <crc> 0d0a`,
//! where the payload is AES-128-CBC encrypted with the lock's key.

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::crc::crc8;
use crate::credential::{AesKey, UnlockKey};
use crate::crypto::{aes_decrypt, aes_encrypt};
use crate::error::{Result, TtlockError};

/// Command byte for a generic response wrapper.
pub const COMM_RESPONSE: u8 = 0x54;
/// Command byte for the check-user-time handshake that precedes every
/// actuation. The lock replies with a challenge (`ps`) to be combined with the
/// unlock key.
pub const COMM_CHECK_USER_TIME: u8 = 0x55;
/// Command byte for unlocking.
pub const COMM_UNLOCK: u8 = 0x47;
/// Command byte for locking. Named for the vendor's "function lock" operation.
pub const COMM_FUNCTION_LOCK: u8 = 0x58;
/// Command byte for querying lock state. The "bicycle" name is the vendor's,
/// inherited from shared-bike hardware built on the same protocol.
pub const COMM_SEARCH_BICYCLE_STATUS: u8 = 0x14;

/// Read the lock's operate log — its own audit trail.
///
/// Records operations the lock performs and never bolt movement it observes,
/// so it is useless for lock state; see section 7a of the design notes.
pub const COMM_GET_OPERATE_LOG: u8 = 0x25;
/// Marker placed in the `encrypt` position to identify app-originated frames.
pub const APP_COMMAND: u8 = 0xaa;
/// Every frame ends with this terminator.
pub const CRLF: [u8; 2] = [0x0d, 0x0a];

/// The protocol header identifying which `TTLock` dialect a lock speaks.
///
/// The lock validates these bytes and rejects commands carrying the wrong
/// ones, so guessing is not harmless: a mismatch surfaces as
/// [`TtlockError::CommandFailed`] on the handshake rather than as a connection
/// error. Prefer the version parsed from an advertisement
/// ([`Advertisement::lock_version`](crate::advertisement::Advertisement::lock_version))
/// and fall back to [`Default`] only when none has been seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockVersion {
    /// Protocol family; 5 for the V3 locks this crate targets.
    pub protocol_type: u8,
    /// Protocol revision within the family.
    pub protocol_version: u8,
    /// Vendor "scene" discriminator, varying by product line.
    pub scene: u8,
    /// Vendor group identifier; 1 for retail locks.
    pub group_id: u16,
    /// Vendor organization identifier; 1 for retail locks.
    pub org_id: u16,
}

impl Default for LockVersion {
    fn default() -> Self {
        Self {
            protocol_type: 5,
            protocol_version: 3,
            // V3 TTLock packets observed for M302/Sciener-style locks use
            // scene 2: 7f 5a 05 03 02 00 01 00 01 ...
            // Advertisement parsing will override this when available.
            scene: 2,
            group_id: 1,
            org_id: 1,
        }
    }
}

/// A parsed frame, still encrypted.
///
/// [`Envelope::parse`] deliberately does not verify the CRC or decrypt;
/// call [`Envelope::ensure_crc`] and then [`Envelope::decrypt_command`]. Keeping
/// the steps separate is what lets a caller distinguish a corrupted frame
/// (retryable) from a wrong key (not).
#[derive(Debug, Clone)]
pub struct Envelope {
    /// See [`LockVersion::protocol_type`].
    pub protocol_type: u8,
    /// See [`LockVersion::protocol_version`].
    pub protocol_version: u8,
    /// See [`LockVersion::scene`].
    pub scene: u8,
    /// See [`LockVersion::group_id`].
    pub group_id: u16,
    /// See [`LockVersion::org_id`].
    pub org_id: u16,
    /// Which command this frame carries.
    pub command_type: u8,
    /// Encryption marker; [`APP_COMMAND`] for frames the app sends.
    pub encrypt: u8,
    /// The still-encrypted payload.
    pub data: Vec<u8>,
    /// The CRC byte carried by the frame.
    pub crc: u8,
    /// The CRC computed over the frame's own bytes. Equal to [`Self::crc`] for
    /// an intact frame.
    pub computed_crc: u8,
}

/// A decrypted command payload.
#[derive(Debug, Clone)]
pub struct PlainCommand {
    /// Which command this is a response to.
    pub command_type: u8,
    /// The lock's status byte: `1` for success, anything else a rejection.
    pub response: u8,
    /// Command-specific payload following the two-byte header.
    pub data: Vec<u8>,
}

impl Envelope {
    /// Parse a raw (CRLF-stripped) frame into an envelope.
    ///
    /// # Errors
    /// Returns an error if the frame is too short, does not start with the
    /// `7f5a` magic, or its length field exceeds the buffer.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < 13 {
            return Err(TtlockError::PacketTooShort);
        }
        if raw.get(0..2) != Some(&[0x7f, 0x5a]) {
            return Err(TtlockError::BadHeader);
        }

        let protocol_type = raw[2];
        let protocol_version = raw[3];
        let scene = raw[4];
        let group_id = u16::from_be_bytes([raw[5], raw[6]]);
        let org_id = u16::from_be_bytes([raw[7], raw[8]]);
        let command_type = raw[9];
        let encrypt = raw[10];
        let len = usize::from(raw[11]);
        let payload_end = 12 + len;
        if raw.len() < payload_end + 1 {
            return Err(TtlockError::BadLength);
        }
        let data = raw[12..payload_end].to_vec();
        let crc = raw[payload_end];
        let computed_crc = crc8(&raw[..payload_end]);

        Ok(Self {
            protocol_type,
            protocol_version,
            scene,
            group_id,
            org_id,
            command_type,
            encrypt,
            data,
            crc,
            computed_crc,
        })
    }

    /// # Errors
    /// Returns [`TtlockError::CrcMismatch`] if the frame CRC does not match
    /// the computed CRC.
    pub const fn ensure_crc(&self) -> Result<()> {
        if self.crc == self.computed_crc {
            Ok(())
        } else {
            Err(TtlockError::CrcMismatch {
                observed: self.crc,
                computed: self.computed_crc,
            })
        }
    }

    /// Decrypt the envelope payload into a plaintext command.
    ///
    /// # Errors
    /// Returns an error if AES decryption fails or the plaintext is shorter
    /// than the two-byte command header.
    pub fn decrypt_command(&self, aes_key: &AesKey) -> Result<PlainCommand> {
        let plain = aes_decrypt(&self.data, aes_key)?;
        if plain.len() < 2 {
            return Err(TtlockError::ShortResponse("plain command header"));
        }
        Ok(PlainCommand {
            command_type: plain[0],
            response: plain[1],
            data: plain[2..].to_vec(),
        })
    }
}

/// Build a complete on-wire frame (including CRC and trailing CRLF).
///
/// # Errors
/// Returns an error if AES encryption fails or the encrypted payload
/// exceeds 255 bytes.
pub fn build_envelope(
    version: LockVersion,
    command_type: u8,
    plaintext: &[u8],
    aes_key: &AesKey,
) -> Result<Vec<u8>> {
    let encrypted = aes_encrypt(plaintext, aes_key);

    let len = u8::try_from(encrypted.len()).map_err(|_| {
        TtlockError::Message("encrypted payload is longer than 255 bytes".to_string())
    })?;

    let mut frame = Vec::with_capacity(13 + encrypted.len() + 2);
    frame.extend_from_slice(&[
        0x7f,
        0x5a,
        version.protocol_type,
        version.protocol_version,
        version.scene,
    ]);
    frame.extend_from_slice(&version.group_id.to_be_bytes());
    frame.extend_from_slice(&version.org_id.to_be_bytes());
    frame.push(command_type);
    frame.push(APP_COMMAND);
    frame.push(len);
    frame.extend_from_slice(&encrypted);
    let crc = crc8(&frame);
    frame.push(crc);
    frame.extend_from_slice(&CRLF);
    Ok(frame)
}

fn date_time_to_bytes(date_time: &str) -> Vec<u8> {
    date_time
        .as_bytes()
        .chunks(2)
        .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        .filter_map(|part| part.parse::<u8>().ok())
        .collect()
}

/// Build the check-user-time payload that opens every actuation.
///
/// The date strings are `YYMMDDHHMM` digit pairs bounding the validity window;
/// callers that hold a permanent key pass a window wide enough to always be
/// valid.
#[must_use]
pub fn build_check_user_time_payload(
    uid: u32,
    start_date: &str,
    end_date: &str,
    lock_flag_pos: u32,
) -> Vec<u8> {
    let mut data = vec![0_u8; 17];
    let start = date_time_to_bytes(start_date);
    let end = date_time_to_bytes(end_date);
    let start_len = start.len().min(data.len());
    data[..start_len].copy_from_slice(&start[..start_len]);
    data[9..13].copy_from_slice(&lock_flag_pos.to_be_bytes());
    let end_len = end.len().min(5);
    data[5..5 + end_len].copy_from_slice(&end[..end_len]);
    data[13..17].copy_from_slice(&uid.to_be_bytes());
    data
}

/// Build the actuation payload, answering the lock's challenge.
///
/// `ps_from_lock` is the challenge returned by
/// [`parse_check_user_time_response`]; adding the unlock key to it proves
/// authorization without ever putting the key on the wire. The current time is
/// appended, which is also how the lock keeps its clock in sync.
#[must_use]
pub fn build_lock_payload(ps_from_lock: u32, unlock_key: UnlockKey) -> Vec<u8> {
    let sum = ps_from_lock.wrapping_add(unlock_key.get());
    let now = u32::try_from(Utc::now().timestamp()).unwrap_or(u32::MAX);
    let mut data = Vec::with_capacity(8);
    data.extend_from_slice(&sum.to_be_bytes());
    data.extend_from_slice(&now.to_be_bytes());
    data
}

/// Extract the lock-provided `ps` value from a check-user-time response.
///
/// # Errors
/// Returns an error if the response is for a different command, reports
/// failure, or is too short.
pub fn parse_check_user_time_response(command: &PlainCommand) -> Result<u32> {
    if command.command_type != COMM_CHECK_USER_TIME {
        return Err(TtlockError::UnexpectedCommand {
            expected: COMM_CHECK_USER_TIME,
            actual: command.command_type,
        });
    }
    if command.response != 1 {
        return Err(TtlockError::CommandFailed {
            command: COMM_CHECK_USER_TIME,
            response: command.response,
        });
    }
    let bytes = command
        .data
        .get(0..4)
        .ok_or(TtlockError::ShortResponse("check-user-time ps"))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// # Errors
/// Returns an error if the response is for a different command or reports
/// failure.
pub const fn parse_success_response(command: &PlainCommand, expected_command: u8) -> Result<()> {
    if command.command_type != expected_command {
        return Err(TtlockError::UnexpectedCommand {
            expected: expected_command,
            actual: command.command_type,
        });
    }
    if command.response == 1 {
        Ok(())
    } else {
        Err(TtlockError::CommandFailed {
            command: expected_command,
            response: command.response,
        })
    }
}

/// Extract the lock state byte from a status response.
///
/// # Errors
/// Returns an error if the response is for a different command, reports
/// failure, or is too short.
pub fn parse_status_response(command: &PlainCommand) -> Result<i32> {
    if command.command_type != COMM_SEARCH_BICYCLE_STATUS {
        return Err(TtlockError::UnexpectedCommand {
            expected: COMM_SEARCH_BICYCLE_STATUS,
            actual: command.command_type,
        });
    }
    if command.response != 1 {
        return Err(TtlockError::CommandFailed {
            command: COMM_SEARCH_BICYCLE_STATUS,
            response: command.response,
        });
    }
    command
        .data
        .get(1)
        .map(|value| i32::from(*value))
        .ok_or(TtlockError::ShortResponse("status byte"))
}

#[cfg(test)]
mod tests {
    use super::{build_check_user_time_payload, build_lock_payload};
    use crate::credential::UnlockKey;

    #[test]
    fn check_user_time_payload_matches_python_size() {
        let payload = build_check_user_time_payload(0, "0001311400", "9911301400", 0);
        assert_eq!(payload.len(), 17);
    }

    #[test]
    fn lock_payload_has_expected_size() {
        let payload = build_lock_payload(1, UnlockKey::ONE);
        assert_eq!(payload.len(), 8);
        assert_eq!(&payload[..4], 2_u32.to_be_bytes());
    }
}
