//! AES-128-CBC as `TTLock` uses it: the key doubles as the IV.

use aes::Aes128;
use cbc::{Decryptor, Encryptor};
use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use crate::credential::AesKey;
use crate::error::{Result, TtlockError};

type Aes128CbcEnc = Encryptor<Aes128>;
type Aes128CbcDec = Decryptor<Aes128>;

/// The factory AES key, used by locks that have never been paired.
///
/// Hardcoded in the vendor firmware and identical across devices, so it is
/// public knowledge rather than a secret. Once a lock is paired it uses the
/// per-lock key from `lockData.json` instead.
pub const DEFAULT_AES_KEY: AesKey = AesKey::from_bytes([
    0x98, 0x76, 0x23, 0xE8, 0xA9, 0x23, 0xA1, 0xBB, 0x3D, 0x9E, 0x7D, 0x03, 0x78, 0x12, 0x45, 0x88,
]);

/// Encrypt `source` with AES-128-CBC, PKCS#7 padded, using `key` as both key
/// and IV.
///
/// Infallible: [`AesKey`] guarantees the one thing that could previously fail
/// here, so this returns a `Vec` rather than a `Result` and callers lost an
/// error path they had to thread through.
#[must_use]
pub fn aes_encrypt(source: &[u8], key: &AesKey) -> Vec<u8> {
    if source.is_empty() {
        return Vec::new();
    }
    let key = key.as_bytes().into();
    Aes128CbcEnc::new(key, key).encrypt_padded_vec_mut::<Pkcs7>(source)
}

/// Decrypt `source`, which was encrypted as [`aes_encrypt`] describes.
///
/// # Errors
/// Returns an error if the ciphertext length is not a multiple of the block
/// size or the PKCS#7 padding is invalid — in practice, the wrong key.
pub fn aes_decrypt(source: &[u8], key: &AesKey) -> Result<Vec<u8>> {
    if source.is_empty() {
        return Ok(Vec::new());
    }
    let key_bytes = key.as_bytes().into();
    Aes128CbcDec::new(key_bytes, key_bytes)
        .decrypt_padded_vec_mut::<Pkcs7>(source)
        .map_err(|_| TtlockError::AesDecrypt)
}

#[cfg(test)]
mod tests {
    use super::{aes_decrypt, aes_encrypt};
    use crate::credential::AesKey;

    #[test]
    fn aes_round_trip() {
        let key = AesKey::from_bytes([0x11; 16]);
        let plain = b"hello";
        let cipher = aes_encrypt(plain, &key);
        let recovered = aes_decrypt(&cipher, &key).unwrap_or_default();
        assert_eq!(recovered, plain);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let cipher = aes_encrypt(b"hello", &AesKey::from_bytes([0x11; 16]));
        assert!(aes_decrypt(&cipher, &AesKey::from_bytes([0x22; 16])).is_err());
    }
}
