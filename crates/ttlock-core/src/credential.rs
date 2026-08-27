//! The credentials that open a lock, and decoding the obfuscated forms of them.
//!
//! [`AesKey`] and [`UnlockKey`] are validated once, here, and are total
//! thereafter: everything downstream takes them by type rather than re-checking
//! a `Vec<u8>` or a bare `u32`. That is deliberate — an unusable credential does
//! not fail loudly, because the lock accepts the command *frame* and merely
//! refuses it, so a bad value surfaces much later as a rejected actuation with
//! nothing pointing back at where it entered.
//!
//! The decoders below handle the app's stored forms: `ZADMINPS` and `ZLOCKKEY`
//! are base64-wrapped comma-separated byte lists whose bytes are the
//! credential's decimal digits `XOR`ed with a mask derived from digit count and
//! a trailing seed byte. The mask differs per value — a fixed constant appears
//! to work against a single sample and then fails.

use std::fmt;
use std::num::NonZeroU32;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::crc::table_value;
use crate::error::{Result, TtlockError};

/// The AES-128 key every packet to and from a lock is encrypted with.
///
/// Sixteen bytes by construction, so the length can never be wrong once one of
/// these exists. That is the point: it removes the check from
/// [`crypto`](crate::crypto) and every builder downstream, and with it the
/// possibility of a 15-byte key reaching the cipher at all.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AesKey([u8; 16]);

impl AesKey {
    /// Wrap sixteen raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Parse the 32-hex-character form found in `lockData.json`.
    ///
    /// Whitespace and `:` separators are ignored, because that is how keys
    /// arrive when pasted out of a database browser or a chat message.
    ///
    /// # Errors
    /// Returns an error if the value is not valid hex or does not decode to
    /// exactly 16 bytes.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let cleaned: String = hex
            .chars()
            .filter(|character| !character.is_whitespace() && *character != ':')
            .collect();
        let bytes = hex::decode(cleaned)?;
        let length = bytes.len();
        let key: [u8; 16] = bytes
            .try_into()
            .map_err(|_| TtlockError::InvalidAesKeyLength(length))?;
        Ok(Self(key))
    }

    /// The raw key material, for handing to the cipher.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Redacted on purpose: this type is held by [`ops`](crate::ops) operations that
/// derive `Debug`, so a plain derive would put the key into any log line that
/// formats an operation.
impl fmt::Debug for AesKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AesKey(<redacted>)")
    }
}

/// The authorization value combined with the lock's challenge to actuate it.
///
/// Non-zero by construction. Zero is not a pedantic exclusion: the actuation
/// payload is `ps_from_lock + unlock_key`, so a zero key sends the challenge
/// back unchanged and the lock refuses it — which is exactly the failure that
/// motivated this type, and which previously reached the wire because the value
/// was an unvalidated `u32` on one side and validated only in a Python config
/// form on the other.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UnlockKey(NonZeroU32);

impl UnlockKey {
    /// The smallest valid key.
    ///
    /// Exists so tests and examples can name *a* key without an `unwrap` and
    /// without implying a real one. Not a default: there is no sensible default
    /// unlock key, which is the whole reason this type exists.
    pub const ONE: Self = match NonZeroU32::new(1) {
        Some(value) => Self(value),
        None => unreachable!(),
    };

    /// Wrap a raw value, rejecting zero.
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        match NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// The raw value, for arithmetic against the lock's challenge.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl FromStr for UnlockKey {
    type Err = TtlockError;

    /// Parse the decimal form, rejecting zero, negatives, fractions, and
    /// anything wider than the `u32` the protocol carries.
    fn from_str(text: &str) -> Result<Self> {
        text.trim()
            .parse::<u32>()
            .ok()
            .and_then(Self::new)
            .ok_or(TtlockError::InvalidUnlockKey)
    }
}

/// Redacted for the same reason as [`AesKey`]: it is a credential, and it is
/// held by types that derive `Debug`.
impl fmt::Debug for UnlockKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnlockKey(<redacted>)")
    }
}

/// Decode an already-parsed byte list into its credential value.
///
/// The final byte is the seed; the rest are masked digits. Returns `None` if
/// the list is empty, the unmasked bytes are not ASCII digits, or the result
/// does not fit in a `u32`.
#[must_use]
pub fn decode_comma_values(values: &[u8]) -> Option<u32> {
    let (seed, body) = values.split_last()?;
    let mask = table_value(body.len()) ^ *seed;
    let digits = body.iter().map(|byte| byte ^ mask).collect::<Vec<u8>>();
    let text = String::from_utf8(digits).ok()?;
    text.parse::<u32>().ok()
}

/// Decode a base64 comma-list `TTLock` credential into its integer form.
///
/// # Errors
/// Returns an error if the value is not valid base64, is not a comma list
/// of bytes, or does not decode to a `u32`.
pub fn decode_base64_credential(value: &str) -> Result<u32> {
    let trimmed = value.trim().trim_end_matches('.');
    let decoded = STANDARD.decode(trimmed)?;
    let csv = String::from_utf8(decoded)?;
    let values = csv
        .trim()
        .split(',')
        .filter(|part| !part.is_empty())
        .map(|part| {
            part.parse::<u8>().map_err(|error| {
                TtlockError::Message(format!("invalid credential byte {part:?}: {error}"))
            })
        })
        .collect::<Result<Vec<u8>>>()?;

    decode_comma_values(&values).ok_or(TtlockError::CredentialOverflow)
}

#[cfg(test)]
mod tests {
    use super::{AesKey, UnlockKey, decode_base64_credential, decode_comma_values};
    use crate::crc::table_value;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use std::str::FromStr as _;

    /// Not a real key: 16 bytes of counting, so a length bug is obvious.
    const SAMPLE_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f";

    #[test]
    fn aes_key_accepts_the_shapes_people_paste() {
        let expected = AesKey::from_hex(SAMPLE_KEY_HEX).ok();
        assert!(expected.is_some());
        for variant in [
            "000102030405060708090A0B0C0D0E0F",
            "  000102030405060708090a0b0c0d0e0f  ",
            "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f",
        ] {
            assert_eq!(
                AesKey::from_hex(variant).ok(),
                expected,
                "failed on {variant:?}"
            );
        }
    }

    #[test]
    fn aes_key_rejects_anything_not_sixteen_bytes() {
        for bad in [
            "",
            "deadbeef",                           // 4 bytes
            "000102030405060708090a0b0c0d0e",     // 15 bytes
            "000102030405060708090a0b0c0d0e0f00", // 17 bytes
            "not hex at all",
            "000102030405060708090a0b0c0d0e0g",
        ] {
            assert!(
                AesKey::from_hex(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn aes_key_debug_does_not_leak_the_key() {
        // `ops::ActuateOp` derives Debug and holds one of these, so a plain
        // derive here would put the key in any log that formats an operation.
        let key = AesKey::from_bytes([0xAB; 16]);
        let rendered = format!("{key:?}");
        assert!(
            !rendered.contains("ab"),
            "key material in Debug: {rendered}"
        );
        assert!(
            !rendered.contains("171"),
            "key material in Debug: {rendered}"
        );
        assert_eq!(rendered, "AesKey(<redacted>)");
    }

    #[test]
    fn unlock_key_rejects_zero_and_out_of_range() {
        assert!(UnlockKey::new(0).is_none());
        for bad in [
            "0",
            "",
            "   ",
            "-1",
            "-12345678",
            "4294967296",
            "12345678.9",
            "abc",
        ] {
            assert!(
                UnlockKey::from_str(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn unlock_key_accepts_valid_values() {
        for (text, expected) in [
            ("1", 1_u32),
            ("  12345678  ", 12_345_678),
            ("4294967295", u32::MAX),
        ] {
            assert_eq!(
                UnlockKey::from_str(text).map(UnlockKey::get).ok(),
                Some(expected),
                "failed on {text:?}"
            );
        }
    }

    #[test]
    fn unlock_key_debug_does_not_leak_the_value() {
        let key = UnlockKey::new(12_345_678).map(|key| format!("{key:?}"));
        assert_eq!(key.as_deref(), Some("UnlockKey(<redacted>)"));
    }

    /// A publicly posted `adminPs` value, used here so the test suite never
    /// contains a credential belonging to a real lock in someone's door.
    /// Source: <https://community.home-assistant.io/t/hass-addon-ttlock-offline-integration/264476/228>
    const PUBLIC_ADMIN_PS: &str = "NjgsNjYsNjUsNzcsNjUsNzAsNjUsNjgsNjQsNjYsMTA=";
    const PUBLIC_ADMIN_PS_DECODED: u32 = 659_525_046;

    /// Inverse of [`decode_comma_values`], for round-trip testing only. The
    /// production code never needs to encode: the app writes these values and
    /// we only ever read them.
    fn encode_comma_values(value: u32, seed: u8) -> Vec<u8> {
        let text = value.to_string();
        let mask = table_value(text.len()) ^ seed;
        let mut values: Vec<u8> = text.bytes().map(|byte| byte ^ mask).collect();
        values.push(seed);
        values
    }

    fn encode_base64_credential(value: u32, seed: u8) -> String {
        let csv = encode_comma_values(value, seed)
            .iter()
            .map(u8::to_string)
            .collect::<Vec<String>>()
            .join(",");
        STANDARD.encode(csv)
    }

    #[test]
    fn decodes_public_admin_ps_example() {
        let decoded = decode_base64_credential(PUBLIC_ADMIN_PS).unwrap_or_default();
        assert_eq!(decoded, PUBLIC_ADMIN_PS_DECODED);
    }

    #[test]
    fn round_trips_across_seeds_and_magnitudes() {
        // The mask depends on both the seed and the digit count, so vary both:
        // a decoder that hardcoded either would pass a single-vector test.
        for seed in [0_u8, 1, 0x74, 0x80, 0xff] {
            for value in [0_u32, 7, 12_345, PUBLIC_ADMIN_PS_DECODED, u32::MAX] {
                let encoded = encode_base64_credential(value, seed);
                assert_eq!(
                    decode_base64_credential(&encoded).unwrap_or_default(),
                    value,
                    "round trip failed for value {value} with seed {seed:#04x}"
                );
            }
        }
    }

    #[test]
    fn mask_is_seed_dependent_not_a_fixed_constant() {
        // A fixed 0x74 mask looked right against one public sample and is
        // wrong; the mask is `table_value(len) ^ seed`. Two encodings of the
        // same value under different seeds must differ on the wire yet decode
        // identically — that is exactly what a hardcoded mask breaks.
        let a = encode_comma_values(PUBLIC_ADMIN_PS_DECODED, 0x10);
        let b = encode_comma_values(PUBLIC_ADMIN_PS_DECODED, 0x74);
        assert_ne!(a, b);
        assert_eq!(decode_comma_values(&a), decode_comma_values(&b));
        assert_eq!(decode_comma_values(&a), Some(PUBLIC_ADMIN_PS_DECODED));
    }

    #[test]
    fn tolerates_whitespace_and_a_trailing_period() {
        // Values copied out of the app's database show up with both.
        let padded = format!("  {PUBLIC_ADMIN_PS}.  ");
        assert_eq!(
            decode_base64_credential(&padded).unwrap_or_default(),
            PUBLIC_ADMIN_PS_DECODED
        );
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in [
            "not base64!!",
            // Valid base64, but not a comma list of byte values.
            &STANDARD.encode("hello, world"),
            // Byte value out of range for u8.
            &STANDARD.encode("300,1,2"),
            // Decodes to digits that overflow a u32.
            &STANDARD.encode("99999999999999999999,0"),
            "",
        ] {
            assert!(
                decode_base64_credential(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn empty_value_list_is_not_a_panic() {
        assert_eq!(decode_comma_values(&[]), None);
    }
}
