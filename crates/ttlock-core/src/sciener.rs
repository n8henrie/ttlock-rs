//! Convert rows of the Sciener app's local database into `lockData.json`
//! entries.
//!
//! The Sciener/TTLock iOS app stores lock credentials in a Core Data sqlite
//! database (`sciener.sqlite`), in a `ZKEY` table. This module is the sans-IO
//! half of the import: it takes the already-read column values of one row
//! ([`ScienerKeyRow`]) and produces the [`LockData`] shape the rest of the
//! project consumes. The actual sqlite reading lives in the CLI crate.
//!
//! Column mapping (`ZKEY` → `lockData.json`):
//!
//! | column         | field                     | transform                          |
//! | -------------- | ------------------------- | ---------------------------------- |
//! | `ZLOCKMAC`     | `address`                 | as-is (`AA:BB:CC:DD:EE:FF`)        |
//! | `ZAESKEYSTR`   | `private_data.aes_key`    | comma-separated hex bytes → hex    |
//! | `ZADMINPS`     | `private_data.admin_ps`   | base64 comma-list credential → u32 |
//! | `ZLOCKKEY`     | `private_data.unlock_key` | base64 comma-list credential → u32 |
//! | `ZAUTOLOCKTIME`| `auto_lock_time`          | integer                            |
//! | `ZRSSI`        | `rssi`                    | integer                            |

use crate::config::{LockData, PrivateData};
use crate::credential::decode_base64_credential;
use crate::error::{Result, TtlockError};

/// Raw values read from one row of the Sciener `ZKEY` table.
///
/// These are the column values before any TTLock-specific decoding. A caller
/// (the CLI's sqlite reader) fills this in from database columns;
/// [`ScienerKeyRow::into_lock_data`] does the decoding.
#[derive(Debug, Clone, Default)]
pub struct ScienerKeyRow {
    /// `ZLOCKMAC` — the lock's BLE MAC address, e.g. `AA:BB:CC:DD:EE:FF`.
    pub lock_mac: Option<String>,
    /// `ZAESKEYSTR` — the AES key as a comma-separated list of hex bytes
    /// (16 bytes, e.g. `1a,2b,3c,...`).
    pub aes_key_csv: Option<String>,
    /// `ZADMINPS` — the admin passcode credential (base64-wrapped comma list).
    pub admin_ps: Option<String>,
    /// `ZLOCKKEY` — the unlock key credential (base64-wrapped comma list).
    pub lock_key: Option<String>,
    /// `ZAUTOLOCKTIME`.
    pub auto_lock_time: Option<i64>,
    /// `ZRSSI`.
    pub rssi: Option<i64>,
}

/// Convert the `ZAESKEYSTR` value — a comma-separated list of hex bytes — into
/// the plain 32-character hex string used by `lockData.json`.
///
/// # Errors
/// Returns an error if any token is not a hex byte or the result is not
/// exactly 16 bytes.
pub fn aes_key_hex_from_csv(csv: &str) -> Result<String> {
    let bytes = csv
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(|token| {
            u8::from_str_radix(token, 16).map_err(|error| {
                TtlockError::Message(format!("invalid AES key byte {token:?}: {error}"))
            })
        })
        .collect::<Result<Vec<u8>>>()?;

    if bytes.len() == 16 {
        Ok(hex::encode(bytes))
    } else {
        Err(TtlockError::InvalidAesKeyLength(bytes.len()))
    }
}

impl ScienerKeyRow {
    /// Convert a raw `ZKEY` row into a [`LockData`] entry.
    ///
    /// The MAC address and AES key are required; the two credentials are
    /// decoded only when present, since not every stored key is an admin key.
    ///
    /// # Errors
    /// Returns an error if the MAC address or AES key is missing, the AES key
    /// is malformed, or a present credential cannot be decoded.
    pub fn into_lock_data(self) -> Result<LockData> {
        let address = self
            .lock_mac
            .filter(|mac| !mac.trim().is_empty())
            .ok_or(TtlockError::MissingLockData("ZLOCKMAC"))?;

        let aes_key = self
            .aes_key_csv
            .filter(|csv| !csv.trim().is_empty())
            .map(|csv| aes_key_hex_from_csv(&csv))
            .transpose()?
            .ok_or(TtlockError::MissingLockData("ZAESKEYSTR"))?;

        let admin_ps = self
            .admin_ps
            .filter(|value| !value.trim().is_empty())
            .map(|value| decode_base64_credential(&value))
            .transpose()?;

        let unlock_key = self
            .lock_key
            .filter(|value| !value.trim().is_empty())
            .map(|value| decode_base64_credential(&value))
            .transpose()?;

        Ok(LockData {
            address,
            battery: -1,
            rssi: self.rssi.and_then(|v| i32::try_from(v).ok()).unwrap_or(0),
            auto_lock_time: self
                .auto_lock_time
                .and_then(|v| i32::try_from(v).ok())
                .unwrap_or(-1),
            locked_status: -1,
            private_data: PrivateData {
                aes_key: Some(aes_key),
                admin_ps,
                unlock_key,
                admin_passcode: None,
                pwd_info: None,
            },
            operation_log: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ScienerKeyRow, aes_key_hex_from_csv};

    // Fabricated, non-secret fixtures. The credential is the public sample
    // documented in the project (decodes to 659_525_046); the AES key is an
    // obviously-fake sequential pattern; the MAC is a placeholder.
    const PUBLIC_CREDENTIAL: &str = "NjgsNjYsNjUsNzcsNjUsNzAsNjUsNjgsNjQsNjYsMTA=";
    const PUBLIC_CREDENTIAL_INT: u32 = 659_525_046;
    const FAKE_AES_CSV: &str = "00,11,22,33,44,55,66,77,88,99,aa,bb,cc,dd,ee,ff";
    const FAKE_AES_HEX: &str = "00112233445566778899aabbccddeeff";
    const FAKE_MAC: &str = "AA:BB:CC:DD:EE:FF";

    fn full_row() -> ScienerKeyRow {
        ScienerKeyRow {
            lock_mac: Some(FAKE_MAC.to_string()),
            aes_key_csv: Some(FAKE_AES_CSV.to_string()),
            admin_ps: Some(PUBLIC_CREDENTIAL.to_string()),
            lock_key: Some(PUBLIC_CREDENTIAL.to_string()),
            auto_lock_time: Some(5),
            rssi: Some(-60),
        }
    }

    #[test]
    fn aes_csv_of_hex_bytes_becomes_hex_string() {
        assert_eq!(
            aes_key_hex_from_csv(FAKE_AES_CSV).unwrap_or_default(),
            FAKE_AES_HEX
        );
    }

    #[test]
    fn aes_csv_tolerates_whitespace_and_uppercase() {
        assert_eq!(
            aes_key_hex_from_csv(" 0A, 0b ,0C,0d,0e,0f,10,11,12,13,14,15,16,17,18,19")
                .unwrap_or_default(),
            "0a0b0c0d0e0f10111213141516171819"
        );
    }

    #[test]
    fn aes_csv_with_wrong_byte_count_is_rejected() {
        assert!(aes_key_hex_from_csv("00,11,22").is_err());
    }

    #[test]
    fn aes_csv_with_non_hex_token_is_rejected() {
        assert!(aes_key_hex_from_csv("00,zz,22,33,44,55,66,77,88,99,aa,bb,cc,dd,ee,ff").is_err());
    }

    #[test]
    fn full_row_maps_every_field() {
        let lock = full_row().into_lock_data().unwrap_or_default();
        assert_eq!(lock.address, FAKE_MAC);
        assert_eq!(lock.private_data.aes_key.as_deref(), Some(FAKE_AES_HEX));
        assert_eq!(lock.private_data.admin_ps, Some(PUBLIC_CREDENTIAL_INT));
        assert_eq!(lock.private_data.unlock_key, Some(PUBLIC_CREDENTIAL_INT));
        assert_eq!(lock.auto_lock_time, 5);
        assert_eq!(lock.rssi, -60);
        assert_eq!(lock.battery, -1);
        assert_eq!(lock.locked_status, -1);
        assert!(lock.operation_log.is_empty());
    }

    #[test]
    fn missing_credentials_decode_to_none() {
        let row = ScienerKeyRow {
            admin_ps: None,
            lock_key: Some(String::new()),
            ..full_row()
        };
        let lock = row.into_lock_data().unwrap_or_default();
        assert_eq!(lock.private_data.admin_ps, None);
        assert_eq!(lock.private_data.unlock_key, None);
        // AES key is still present.
        assert_eq!(lock.private_data.aes_key.as_deref(), Some(FAKE_AES_HEX));
    }

    #[test]
    fn missing_mac_is_an_error() {
        let row = ScienerKeyRow {
            lock_mac: None,
            ..full_row()
        };
        assert!(row.into_lock_data().is_err());
    }

    #[test]
    fn missing_aes_key_is_an_error() {
        let row = ScienerKeyRow {
            aes_key_csv: None,
            ..full_row()
        };
        assert!(row.into_lock_data().is_err());
    }

    #[test]
    fn defaults_apply_when_optional_integers_absent() {
        let row = ScienerKeyRow {
            auto_lock_time: None,
            rssi: None,
            ..full_row()
        };
        let lock = row.into_lock_data().unwrap_or_default();
        assert_eq!(lock.auto_lock_time, -1);
        assert_eq!(lock.rssi, 0);
    }
}
