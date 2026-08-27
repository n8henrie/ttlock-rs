//! Protocol-level constants and the connect-backoff schedule.
//!
//! These are properties of the locks and of BLE, not of any one transport, so
//! every consumer must agree on them. They lived in both
//! `crates/ttlock/src/ble.rs` and the Home Assistant component's `const.py`
//! until the two copies started to drift.
//!
//! Note what is deliberately *not* here: response timeouts and connect-attempt
//! counts. Those legitimately differ by transport — an `ESPHome` Bluetooth proxy
//! is slower and busier than a local adapter — so each consumer sets its own,
//! next to a comment saying why. The table in `docs/protocol-and-design.md`
//! records the differences so they stay deliberate.

use std::time::Duration;

/// `TTLock`'s primary GATT service UUID (16-bit `0x1910` expanded to 128 bits).
///
/// Only ever corroborates a match — never filters a scan. The locks do not
/// advertise it (it appears in the GATT table after connecting), so filtering
/// on it silently suppresses every advertisement report.
pub const SERVICE_UUID: &str = "00001910-0000-1000-8000-00805f9b34fb";

/// Characteristic the app writes command frames to.
pub const WRITE_CHARACTERISTIC: &str = "0000fff2-0000-1000-8000-00805f9b34fb";

/// Characteristic the lock sends response notifications on.
pub const NOTIFY_CHARACTERISTIC: &str = "0000fff4-0000-1000-8000-00805f9b34fb";

/// Bytes per GATT write, sized for the default ATT MTU.
pub const WRITE_CHUNK: usize = 20;

/// How many times to re-send a frame whose response failed its CRC check.
///
/// Safe to retry precisely because operations verify the CRC before advancing
/// any state, so a rejected frame leaves the exchange where it was.
pub const CRC_RETRIES: u32 = 2;

/// How long to pause before re-sending a frame after a CRC failure.
pub const CRC_RETRY_DELAY: Duration = Duration::from_millis(200);

/// How many unsolicited frames to skip while waiting for a command's reply.
///
/// The lock pushes notifications on the characteristic it also replies on, so
/// one can land inside a response window; see
/// [`TtlockError::is_stale_frame`](crate::error::TtlockError::is_stale_frame).
/// Bounded rather than unlimited so a genuine desynchronization still surfaces
/// as an error instead of decaying into a timeout — and low, because a lock
/// that interleaves more than a handful of pushes into one exchange is not in a
/// state worth pressing on with.
pub const MAX_STRAY_FRAMES: u32 = 4;

/// Pause between GATT write chunks.
///
/// Writes are sent *without* response, so nothing applies back-pressure: a
/// slower controller, or a proxy relaying over Wi-Fi, can drop a chunk. A frame
/// that reaches the lock truncated is refused rather than retried, so the cost
/// of not pacing is a mystery rejection.
pub const WRITE_CHUNK_DELAY: Duration = Duration::from_millis(20);

/// Base delay before retrying a failed scan-and-connect.
const CONNECT_BACKOFF_BASE: Duration = Duration::from_millis(750);

/// Ceiling on the connect backoff.
const CONNECT_BACKOFF_MAX: Duration = Duration::from_secs(4);

/// How long to wait before connect attempt `attempt` (1-based).
///
/// Doubles and then caps. The growth matters as much as the retry count: a
/// controller needs a moment to settle after an aborted connection, and
/// `le-connection-abort-by-local` on a weak link usually clears on a later try.
/// The cap keeps a raised attempt limit buying attempts rather than waiting.
#[must_use]
pub fn connect_backoff(attempt: u32) -> Duration {
    // saturating_sub keeps a 0 from underflowing; attempts are 1-based.
    (CONNECT_BACKOFF_BASE * 2_u32.pow(attempt.saturating_sub(1).min(3))).min(CONNECT_BACKOFF_MAX)
}

#[cfg(test)]
mod tests {
    use super::connect_backoff;
    use std::time::Duration;

    #[test]
    fn connect_backoff_grows_then_caps() {
        assert_eq!(connect_backoff(1), Duration::from_millis(750));
        assert_eq!(connect_backoff(2), Duration::from_millis(1500));
        assert_eq!(connect_backoff(3), Duration::from_secs(3));
        // Capped, so raising --connect-attempts buys attempts rather than waiting.
        assert_eq!(connect_backoff(4), Duration::from_secs(4));
        assert_eq!(connect_backoff(50), Duration::from_secs(4));
    }

    #[test]
    fn connect_backoff_tolerates_a_zero_attempt() {
        assert_eq!(connect_backoff(0), Duration::from_millis(750));
    }
}
