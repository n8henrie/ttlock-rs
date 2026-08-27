//! Sans-IO state machines for user-level lock operations.
//!
//! Each operation yields frames to write via [`Step::Write`]; the caller
//! (whatever owns the transport) writes the frame, waits for the next
//! reassembled response frame, and feeds it back through
//! [`Operation::handle_frame`] until [`Step::Done`] is produced.

use crate::credential::{AesKey, UnlockKey};
use crate::error::{Result, TtlockError};
use crate::packet::{
    COMM_CHECK_USER_TIME, COMM_FUNCTION_LOCK, COMM_SEARCH_BICYCLE_STATUS, COMM_UNLOCK, Envelope,
    LockVersion, build_check_user_time_payload, build_envelope, build_lock_payload,
    parse_check_user_time_response, parse_status_response, parse_success_response,
};

/// Parse, CRC-check, and decrypt one response frame.
fn decrypt_response(raw: &[u8], aes_key: &AesKey) -> Result<crate::packet::PlainCommand> {
    let envelope = Envelope::parse(raw)?;
    envelope.ensure_crc()?;
    envelope.decrypt_command(aes_key)
}

fn unexpected_frame() -> TtlockError {
    TtlockError::Message("received a frame when none was expected".to_string())
}

/// Which way to move the bolt.
///
/// Lives here rather than in a consumer because the tracker, the CLI and the
/// MQTT bridge all need to name an actuation, and three copies of a two-variant
/// enum is how the two sides of this project drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actuation {
    /// Throw the bolt ([`COMM_FUNCTION_LOCK`]).
    Lock,
    /// Retract the bolt ([`COMM_UNLOCK`]).
    Unlock,
}

impl Actuation {
    /// The protocol command byte this actuation sends.
    #[must_use]
    pub const fn command_type(self) -> u8 {
        match self {
            Self::Lock => COMM_FUNCTION_LOCK,
            Self::Unlock => COMM_UNLOCK,
        }
    }

    /// Build the operation that performs this actuation.
    #[must_use]
    pub const fn op(
        self,
        aes_key: AesKey,
        unlock_key: UnlockKey,
        version: LockVersion,
    ) -> ActuateOp {
        ActuateOp::new(self.command_type(), aes_key, unlock_key, version)
    }
}

/// What the transport should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step<T> {
    /// Write this frame to the lock and wait for a response frame.
    Write(Vec<u8>),
    /// The operation completed.
    Done(T),
}

/// A protocol exchange, driven by the caller.
///
/// Operations own no transport. Call [`start`](Self::start) for the first frame
/// to write, then feed each reassembled response to
/// [`handle_frame`](Self::handle_frame) until it yields [`Step::Done`]. That is
/// what lets one implementation back a `btleplug` CLI, a `bleak` Home Assistant
/// component, and anything else that can move bytes.
///
/// An operation is single-use: once it reaches [`Step::Done`] it cannot be
/// restarted, and a retry needs a fresh one. A [`TtlockError::CrcMismatch`] is
/// the exception — it is reported before any state advances, so re-sending the
/// previous frame resumes the exchange rather than desynchronizing it.
pub trait Operation {
    /// What the operation produces when it completes.
    type Output;

    /// Produce the first frame to write.
    ///
    /// # Errors
    /// Returns an error if the initial frame cannot be built (for example,
    /// an invalid AES key) or if the operation was already started.
    fn start(&mut self) -> Result<Step<Self::Output>>;

    /// Feed one reassembled response frame (without CRLF).
    ///
    /// # Errors
    /// Returns an error if the frame cannot be parsed or decrypted, fails
    /// CRC (the caller may re-send the previous write), reports a failure
    /// response, or arrives when no frame is expected.
    fn handle_frame(&mut self, raw: &[u8]) -> Result<Step<Self::Output>>;
}

/// Lock state reported by the status command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// The bolt is thrown.
    Locked,
    /// The bolt is retracted.
    Unlocked,
    /// A status byte this crate does not recognize, preserved as-is rather
    /// than guessed at — reporting a door as locked on a guess would be worse
    /// than reporting it as unknown.
    Unknown(u8),
}

impl From<u8> for LockState {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Locked,
            1 => Self::Unlocked,
            other => Self::Unknown(other),
        }
    }
}

/// Query the lock/unlock state.
#[derive(Debug)]
pub struct StatusOp {
    aes_key: AesKey,
    version: LockVersion,
    awaiting_response: bool,
}

impl StatusOp {
    /// Build a status query for a lock with the given key and protocol version.
    #[must_use]
    pub const fn new(aes_key: AesKey, version: LockVersion) -> Self {
        Self {
            aes_key,
            version,
            awaiting_response: false,
        }
    }
}

impl Operation for StatusOp {
    type Output = LockState;

    fn start(&mut self) -> Result<Step<LockState>> {
        let frame = build_envelope(
            self.version,
            COMM_SEARCH_BICYCLE_STATUS,
            b"SCIENER",
            &self.aes_key,
        )?;
        self.awaiting_response = true;
        Ok(Step::Write(frame))
    }

    fn handle_frame(&mut self, raw: &[u8]) -> Result<Step<LockState>> {
        if !self.awaiting_response {
            return Err(unexpected_frame());
        }
        let plain = decrypt_response(raw, &self.aes_key)?;
        let state = parse_status_response(&plain)?;
        self.awaiting_response = false;
        Ok(Step::Done(LockState::from(
            u8::try_from(state).unwrap_or(u8::MAX),
        )))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActuateState {
    Idle,
    AwaitingCheckUserTime,
    AwaitingActuate,
    Done,
}

/// Shared state machine for lock and unlock.
///
/// A check-user-time handshake followed by the actuation command. Lock and
/// unlock differ only in the command byte ([`COMM_FUNCTION_LOCK`] vs
/// [`COMM_UNLOCK`]); the payload is identical. Usually reached through
/// [`Actuation::op`], or through the named [`LockOp`]/[`UnlockOp`] wrappers.
#[derive(Debug)]
pub struct ActuateOp {
    command_type: u8,
    aes_key: AesKey,
    unlock_key: UnlockKey,
    version: LockVersion,
    state: ActuateState,
}

impl ActuateOp {
    const fn new(
        command_type: u8,
        aes_key: AesKey,
        unlock_key: UnlockKey,
        version: LockVersion,
    ) -> Self {
        Self {
            command_type,
            aes_key,
            unlock_key,
            version,
            state: ActuateState::Idle,
        }
    }
}

impl Operation for ActuateOp {
    type Output = ();

    fn start(&mut self) -> Result<Step<()>> {
        let payload = build_check_user_time_payload(0, "0001311400", "9911301400", 0);
        let frame = build_envelope(self.version, COMM_CHECK_USER_TIME, &payload, &self.aes_key)?;
        self.state = ActuateState::AwaitingCheckUserTime;
        Ok(Step::Write(frame))
    }

    fn handle_frame(&mut self, raw: &[u8]) -> Result<Step<()>> {
        match self.state {
            ActuateState::AwaitingCheckUserTime => {
                let plain = decrypt_response(raw, &self.aes_key)?;
                let ps_from_lock = parse_check_user_time_response(&plain)?;
                let payload = build_lock_payload(ps_from_lock, self.unlock_key);
                let frame =
                    build_envelope(self.version, self.command_type, &payload, &self.aes_key)?;
                self.state = ActuateState::AwaitingActuate;
                Ok(Step::Write(frame))
            }
            ActuateState::AwaitingActuate => {
                let plain = decrypt_response(raw, &self.aes_key)?;
                parse_success_response(&plain, self.command_type)?;
                self.state = ActuateState::Done;
                Ok(Step::Done(()))
            }
            ActuateState::Idle | ActuateState::Done => Err(unexpected_frame()),
        }
    }
}

/// Lock the lock: check-user-time handshake followed by function-lock
/// ([`COMM_FUNCTION_LOCK`]).
#[derive(Debug)]
pub struct LockOp(ActuateOp);

impl LockOp {
    /// Build a lock command for a lock with the given credentials and protocol
    /// version.
    #[must_use]
    pub const fn new(aes_key: AesKey, unlock_key: UnlockKey, version: LockVersion) -> Self {
        Self(ActuateOp::new(
            COMM_FUNCTION_LOCK,
            aes_key,
            unlock_key,
            version,
        ))
    }
}

impl Operation for LockOp {
    type Output = ();

    fn start(&mut self) -> Result<Step<()>> {
        self.0.start()
    }

    fn handle_frame(&mut self, raw: &[u8]) -> Result<Step<()>> {
        self.0.handle_frame(raw)
    }
}

/// Unlock the lock: check-user-time handshake followed by unlock
/// ([`COMM_UNLOCK`]).
#[derive(Debug)]
pub struct UnlockOp(ActuateOp);

impl UnlockOp {
    /// Build an unlock command for a lock with the given credentials and
    /// protocol version.
    #[must_use]
    pub const fn new(aes_key: AesKey, unlock_key: UnlockKey, version: LockVersion) -> Self {
        Self(ActuateOp::new(COMM_UNLOCK, aes_key, unlock_key, version))
    }
}

impl Operation for UnlockOp {
    type Output = ();

    fn start(&mut self) -> Result<Step<()>> {
        self.0.start()
    }

    fn handle_frame(&mut self, raw: &[u8]) -> Result<Step<()>> {
        self.0.handle_frame(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::{LockOp, LockState, Operation, StatusOp, Step, UnlockOp};
    use crate::credential::{AesKey, UnlockKey};
    use crate::error::{Result, TtlockError};
    use crate::packet::{
        COMM_CHECK_USER_TIME, COMM_FUNCTION_LOCK, COMM_SEARCH_BICYCLE_STATUS, COMM_UNLOCK,
        Envelope, LockVersion, build_envelope,
    };

    fn test_key() -> AesKey {
        AesKey::from_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
    }

    /// Tests name a key by value; this turns one into the type without an
    /// `unwrap` (the workspace denies those) by falling back to 1, which is
    /// still a valid key and so cannot mask a rejection.
    fn key(value: u32) -> UnlockKey {
        UnlockKey::new(value).unwrap_or(UnlockKey::ONE)
    }

    fn unexpected(message: &str) -> TtlockError {
        TtlockError::Message(message.to_string())
    }

    /// Build a lock->app response frame (CRLF stripped) whose decrypted
    /// plaintext is `plain`.
    fn response_frame(plain: &[u8]) -> Result<Vec<u8>> {
        let mut wire = build_envelope(LockVersion::default(), plain[0], plain, &test_key())?;
        wire.truncate(wire.len().saturating_sub(2));
        Ok(wire)
    }

    fn decrypt_write(frame: &[u8]) -> Result<(u8, Vec<u8>)> {
        let envelope = Envelope::parse(frame)?;
        let plain = crate::crypto::aes_decrypt(&envelope.data, &test_key())?;
        Ok((envelope.command_type, plain))
    }

    #[test]
    fn status_op_writes_status_command_then_completes() -> Result<()> {
        let mut op = StatusOp::new(test_key(), LockVersion::default());
        let Step::Write(frame) = op.start()? else {
            return Err(unexpected("start did not yield a write"));
        };
        let (command, plain) = decrypt_write(&frame)?;
        assert_eq!(command, COMM_SEARCH_BICYCLE_STATUS);
        assert_eq!(&plain, b"SCIENER");

        let response = response_frame(&[COMM_SEARCH_BICYCLE_STATUS, 0x01, 0x63, 0x00])?;
        let step = op.handle_frame(&response)?;
        assert_eq!(step, Step::Done(LockState::Locked));
        Ok(())
    }

    #[test]
    fn status_op_maps_state_bytes() -> Result<()> {
        for (byte, expected) in [
            (0x00, LockState::Locked),
            (0x01, LockState::Unlocked),
            (0x02, LockState::Unknown(2)),
        ] {
            let mut op = StatusOp::new(test_key(), LockVersion::default());
            let _ = op.start()?;
            let response = response_frame(&[COMM_SEARCH_BICYCLE_STATUS, 0x01, 0x63, byte])?;
            let step = op.handle_frame(&response)?;
            assert_eq!(step, Step::Done(expected));
        }
        Ok(())
    }

    #[test]
    fn status_op_rejects_frame_before_start() -> Result<()> {
        let mut op = StatusOp::new(test_key(), LockVersion::default());
        let response = response_frame(&[COMM_SEARCH_BICYCLE_STATUS, 0x01, 0x63, 0x00])?;
        assert!(op.handle_frame(&response).is_err());
        Ok(())
    }

    #[test]
    fn status_op_surfaces_crc_mismatch() -> Result<()> {
        let mut op = StatusOp::new(test_key(), LockVersion::default());
        let _ = op.start()?;
        let mut response = response_frame(&[COMM_SEARCH_BICYCLE_STATUS, 0x01, 0x63, 0x00])?;
        if let Some(last) = response.last_mut() {
            *last ^= 0xff;
        }
        assert!(matches!(
            op.handle_frame(&response),
            Err(TtlockError::CrcMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn lock_op_runs_check_user_time_then_lock() -> Result<()> {
        let unlock_key = key(43_210);
        let ps = 98_765_u32;
        let mut op = LockOp::new(test_key(), unlock_key, LockVersion::default());

        let Step::Write(first) = op.start()? else {
            return Err(unexpected("start did not yield a write"));
        };
        let (command, plain) = decrypt_write(&first)?;
        assert_eq!(command, COMM_CHECK_USER_TIME);
        assert_eq!(plain.len(), 17);

        let mut response_plain = vec![COMM_CHECK_USER_TIME, 0x01];
        response_plain.extend_from_slice(&ps.to_be_bytes());
        let Step::Write(second) = op.handle_frame(&response_frame(&response_plain)?)? else {
            return Err(unexpected(
                "check-user-time response did not yield the lock write",
            ));
        };
        let (command, plain) = decrypt_write(&second)?;
        assert_eq!(command, COMM_FUNCTION_LOCK);
        assert_eq!(plain.len(), 8);
        assert_eq!(&plain[..4], ps.wrapping_add(unlock_key.get()).to_be_bytes());

        let done = op.handle_frame(&response_frame(&[COMM_FUNCTION_LOCK, 0x01])?)?;
        assert_eq!(done, Step::Done(()));
        Ok(())
    }

    #[test]
    fn an_unsolicited_frame_does_not_advance_an_operation() -> Result<()> {
        // The lock pushes notifications on the same characteristic it replies
        // on, so one can land inside a command's response window. Every
        // lock-to-phone frame carries COMM_RESPONSE at the envelope level, so
        // only the decrypted plaintext distinguishes them — which is why the
        // operation, not the transport, has to reject it. Consuming a push as
        // the reply would report a state the lock never sent and leave the real
        // reply queued, desynchronizing every later exchange by one frame.
        let mut op = StatusOp::new(test_key(), LockVersion::default());
        let Step::Write(_) = op.start()? else {
            return Err(unexpected("start did not yield a write"));
        };

        let push = response_frame(&[COMM_UNLOCK, 0x01, 0x00, 0x00])?;
        let error = op
            .handle_frame(&push)
            .err()
            .ok_or_else(|| unexpected("a mismatched frame should not be accepted"))?;
        assert!(
            error.is_stale_frame(),
            "an unsolicited frame must be classified as skippable, got {error}"
        );

        // The genuine reply still completes: no state advanced, so the caller
        // could simply keep reading rather than re-sending or failing.
        let reply = response_frame(&[COMM_SEARCH_BICYCLE_STATUS, 0x01, 0x63, 0x00])?;
        assert_eq!(op.handle_frame(&reply)?, Step::Done(LockState::Locked));
        Ok(())
    }

    #[test]
    fn an_unsolicited_frame_does_not_advance_an_actuation() -> Result<()> {
        // Same property on the two-step exchange, where a lost position in the
        // handshake would send the actuation with the wrong challenge.
        let mut op = LockOp::new(test_key(), key(43_210), LockVersion::default());
        let _ = op.start()?;

        let push = response_frame(&[COMM_SEARCH_BICYCLE_STATUS, 0x01, 0x63, 0x00])?;
        let error = op
            .handle_frame(&push)
            .err()
            .ok_or_else(|| unexpected("a mismatched frame should not be accepted"))?;
        assert!(error.is_stale_frame(), "got {error}");

        // Still awaiting the handshake reply, so the exchange resumes normally.
        let ps: u32 = 98_765;
        let mut plain = vec![COMM_CHECK_USER_TIME, 0x01];
        plain.extend_from_slice(&[0, 0, 0, 0]);
        plain.extend_from_slice(&ps.to_be_bytes());
        let Step::Write(_) = op.handle_frame(&response_frame(&plain)?)? else {
            return Err(unexpected(
                "handshake reply did not yield the actuation write",
            ));
        };
        Ok(())
    }

    #[test]
    fn lock_op_propagates_command_failure() -> Result<()> {
        let mut op = LockOp::new(test_key(), UnlockKey::ONE, LockVersion::default());
        let _ = op.start()?;
        let failure = response_frame(&[COMM_CHECK_USER_TIME, 0x00])?;
        // A rejection at the handshake is reported as the handshake command, not
        // the actuation: the two point at different causes (AES key / protocol
        // version vs. unlock key), so conflating them loses the diagnosis.
        assert!(matches!(
            op.handle_frame(&failure),
            Err(TtlockError::CommandFailed {
                command: COMM_CHECK_USER_TIME,
                response: 0
            })
        ));
        Ok(())
    }

    #[test]
    fn lock_op_reports_actuation_failure_against_the_lock_command() -> Result<()> {
        let unlock_key = key(7);
        let ps = 11_u32;
        let mut op = LockOp::new(test_key(), unlock_key, LockVersion::default());
        let _ = op.start()?;
        // Pass the handshake, then reject the actuation itself.
        let mut ps_payload = ps.to_be_bytes().to_vec();
        let mut handshake = vec![COMM_CHECK_USER_TIME, 0x01];
        handshake.append(&mut ps_payload);
        let _ = op.handle_frame(&response_frame(&handshake)?)?;
        assert!(matches!(
            op.handle_frame(&response_frame(&[COMM_FUNCTION_LOCK, 0x00])?),
            Err(TtlockError::CommandFailed {
                command: COMM_FUNCTION_LOCK,
                response: 0
            })
        ));
        Ok(())
    }

    #[test]
    fn unlock_op_runs_check_user_time_then_unlock() -> Result<()> {
        let unlock_key = key(43_210);
        let ps = 98_765_u32;
        let mut op = UnlockOp::new(test_key(), unlock_key, LockVersion::default());

        let Step::Write(first) = op.start()? else {
            return Err(unexpected("start did not yield a write"));
        };
        let (command, _) = decrypt_write(&first)?;
        assert_eq!(command, COMM_CHECK_USER_TIME);

        let mut response_plain = vec![COMM_CHECK_USER_TIME, 0x01];
        response_plain.extend_from_slice(&ps.to_be_bytes());
        let Step::Write(second) = op.handle_frame(&response_frame(&response_plain)?)? else {
            return Err(unexpected(
                "check-user-time response did not yield the unlock write",
            ));
        };
        let (command, plain) = decrypt_write(&second)?;
        // Unlock uses COMM_UNLOCK (0x47), not COMM_FUNCTION_LOCK (0x58), with
        // the same 8-byte (sum || timestamp) payload as lock.
        assert_eq!(command, COMM_UNLOCK);
        assert_eq!(plain.len(), 8);
        assert_eq!(&plain[..4], ps.wrapping_add(unlock_key.get()).to_be_bytes());

        let done = op.handle_frame(&response_frame(&[COMM_UNLOCK, 0x01])?)?;
        assert_eq!(done, Step::Done(()));
        Ok(())
    }
}
