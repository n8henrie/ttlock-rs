//! Reading and selecting entries from a `lockData.json` credential file.
//!
//! The format is inherited from the Python proof-of-concept this crate was
//! ported from: either a single lock object or an array of them.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::credential::{AesKey, UnlockKey};
use crate::error::{Result, TtlockError};

/// One lock's entry in `lockData.json`.
///
/// Every field is optional on the wire: files written by different tools carry
/// different subsets, so missing keys deserialize to defaults rather than
/// failing. Use [`LockData::aes_key`] and [`LockData::unlock_key`] to read the
/// credentials: they validate once and hand back types that cannot afterwards
/// be the wrong length or zero.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct LockData {
    /// The lock's BLE MAC address, e.g. `AA:BB:CC:DD:EE:FF`.
    #[serde(default)]
    pub address: String,
    /// Battery percentage as last recorded by whatever wrote the file. The
    /// live value comes from advertisements instead.
    #[serde(default)]
    pub battery: i32,
    /// Signal strength as last recorded. Informational only.
    #[serde(default)]
    pub rssi: i32,
    /// The lock's auto-lock delay in seconds, as configured in the app.
    #[serde(default)]
    pub auto_lock_time: i32,
    /// Lock state as last recorded. Informational only.
    #[serde(default)]
    pub locked_status: i32,
    /// The credentials needed to talk to the lock.
    #[serde(default)]
    pub private_data: PrivateData,
    /// Operation history, preserved verbatim so a round trip through this type
    /// does not discard it. Not interpreted by this crate.
    #[serde(default)]
    pub operation_log: Vec<serde_json::Value>,
}

/// The secret half of a [`LockData`] entry.
///
/// These values open the door. Treat a file containing them like a private
/// key: never commit it, and never place it in a world-readable location such
/// as the Nix store.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PrivateData {
    /// AES-128 key as 32 hex characters. Every packet to and from the lock is
    /// encrypted with it.
    pub aes_key: Option<String>,
    /// Admin passcode. Not needed for lock/unlock; carried for completeness.
    pub admin_ps: Option<u32>,
    /// The authorization value combined with the lock's challenge during the
    /// check-user-time handshake. Required to actuate the lock.
    pub unlock_key: Option<u32>,
    /// Admin passcode in its original string form, when the source preserved
    /// leading zeros.
    pub admin_passcode: Option<String>,
    /// Passcode metadata, preserved verbatim and not interpreted here.
    pub pwd_info: Option<serde_json::Value>,
}

impl LockData {
    /// The AES-128 key.
    ///
    /// # Errors
    /// Returns an error if the AES key is missing, is not valid hex, or is
    /// not exactly 16 bytes.
    pub fn aes_key(&self) -> Result<AesKey> {
        self.private_data
            .aes_key
            .as_deref()
            .ok_or(TtlockError::MissingLockData("private_data.aes_key"))
            .and_then(AesKey::from_hex)
    }

    /// The unlock key used to authorize lock and unlock commands.
    ///
    /// # Errors
    /// Returns an error if the unlock key is missing, or is present but cannot
    /// be a key — most often `0`, which is what a field left unfilled becomes.
    /// Catching that here rather than on the wire matters: the lock accepts the
    /// resulting frame and merely refuses it, so the mistake would otherwise
    /// surface as a protocol error with nothing pointing at this file.
    pub fn unlock_key(&self) -> Result<UnlockKey> {
        self.private_data
            .unlock_key
            .ok_or(TtlockError::MissingLockData("private_data.unlock_key"))
            .and_then(|value| UnlockKey::new(value).ok_or(TtlockError::InvalidUnlockKey))
    }
}

/// Load one or more lock entries from a Python-project `lockData.json` file.
///
/// # Errors
/// Returns an error if the file cannot be read or parsed.
pub fn load_lock_data(path: &Path) -> Result<Vec<LockData>> {
    let text = fs::read_to_string(path)?;
    let trimmed = text.trim_start();
    if trimmed.starts_with('[') {
        Ok(serde_json::from_str(&text)?)
    } else {
        Ok(vec![serde_json::from_str(&text)?])
    }
}

/// Select a lock entry by address, or the first entry when no address is
/// given.
///
/// # Errors
/// Returns an error if no entry matches or the list is empty.
pub fn select_lock<'a>(locks: &'a [LockData], address: Option<&str>) -> Result<&'a LockData> {
    if let Some(target) = address {
        return locks
            .iter()
            .find(|lock| lock.address.eq_ignore_ascii_case(target))
            .ok_or_else(|| {
                TtlockError::Message(format!("no lockData entry matches address {target}"))
            });
    }

    locks
        .first()
        .ok_or(TtlockError::MissingLockData("at least one lockData entry"))
}
