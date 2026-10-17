use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, AeadCore, OsRng},
};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::CryptoError;

pub const DEK_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

pub fn generate_dek() -> Zeroizing<Vec<u8>> {
    let mut dek = Zeroizing::new(vec![0u8; DEK_LEN]);
    rand::rng().fill_bytes(dek.as_mut());
    dek
}

/// AES-256-GCM encrypt: returns `(nonce, ciphertext_with_tag)`.
pub fn encrypt_blob(dek: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(dek);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::Crypto(e.to_string()))?;
    Ok((nonce.to_vec(), ciphertext))
}

pub fn decrypt_blob(dek: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::Crypto(format!(
            "invalid nonce length {}",
            nonce.len()
        )));
    }
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(dek);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::Crypto(e.to_string()))
}

/// Wrap a DEK with a 32-byte KEK (AES-GCM).
pub fn wrap_dek(kek: &[u8], dek: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    encrypt_blob(kek, dek)
}

pub fn unwrap_dek(kek: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let plain = decrypt_blob(kek, nonce, ciphertext)?;
    Ok(Zeroizing::new(plain))
}
