//! Object AEAD: XChaCha20-Poly1305 under `ObjectKey`.
//!
//! Plaintext is `kind || schema || payload`. The production nonce comes from
//! the operating system CSPRNG. A fixed nonce is available only while this
//! crate is built for tests, and that function is not part of the release
//! library.

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{AeadInOut, KeyInit},
};
use zeroize::Zeroize;

use crate::{CryptoError, ObjectKey};

const TAG_LEN: usize = 16;
/// `kind || schema`, with an empty payload.
pub const MIN_OBJECT_PLAINTEXT_LEN: usize = 2;
/// Envelope cap: 1,048,576 bytes of plaintext.
pub const MAX_OBJECT_PLAINTEXT_LEN: usize = 1_048_576;
/// Shortest ciphertext: 2-byte plaintext plus a 16-byte tag.
pub const MIN_OBJECT_CIPHERTEXT_LEN: usize = MIN_OBJECT_PLAINTEXT_LEN + TAG_LEN;
/// Longest ciphertext: maximum plaintext plus a 16-byte tag.
pub const MAX_OBJECT_CIPHERTEXT_LEN: usize = MAX_OBJECT_PLAINTEXT_LEN + TAG_LEN;

/// Nonce and `ciphertext || tag` for one sealed object body.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedObject {
    pub nonce: [u8; 24],
    pub ciphertext_and_tag: Vec<u8>,
}

impl std::fmt::Debug for EncryptedObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedObject")
            .field("nonce_len", &self.nonce.len())
            .field("ciphertext_len", &self.ciphertext_and_tag.len())
            .finish()
    }
}

/// Seal `kind || schema || payload` with a fresh 24-byte OS nonce.
///
/// Every call draws a new nonce, including when `plaintext` matches an earlier
/// call. Identical plaintexts therefore produce different ciphertexts. This
/// function does not look at a previous ciphertext: doing so would reveal
/// whether two plaintexts are equal. Storage idempotency, if needed, is keyed
/// by object id and content hash outside this crate.
pub fn encrypt_authenticated(
    key: &ObjectKey,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<EncryptedObject, CryptoError> {
    check_plaintext(plaintext)?;
    let nonce = os_nonce()?;
    seal_with_nonce(key, &nonce, aad, plaintext)
}

/// Open a sealed object body. The plaintext is returned only after the tag check.
pub fn decrypt_authenticated(
    key: &ObjectKey,
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    open_plaintext(key, nonce, aad, ciphertext_and_tag)
}

/// Seal with a nonce the caller already drew.
///
/// The vault draws that nonce from the OS CSPRNG and places the same bytes in
/// the object header before calling this. A fixed nonce belongs in tests.
pub fn seal_authenticated(
    key: &ObjectKey,
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<EncryptedObject, CryptoError> {
    check_plaintext(plaintext)?;
    seal_with_nonce(key, nonce, aad, plaintext)
}

fn check_plaintext(plaintext: &[u8]) -> Result<(), CryptoError> {
    if (MIN_OBJECT_PLAINTEXT_LEN..=MAX_OBJECT_PLAINTEXT_LEN).contains(&plaintext.len()) {
        Ok(())
    } else {
        Err(CryptoError::UnsupportedParameters)
    }
}

fn os_nonce() -> Result<[u8; 24], CryptoError> {
    let mut nonce = [0u8; 24];
    if getrandom::fill(&mut nonce).is_err() {
        nonce.zeroize();
        return Err(CryptoError::Unavailable);
    }
    Ok(nonce)
}

fn seal_with_nonce(
    key: &ObjectKey,
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<EncryptedObject, CryptoError> {
    let cipher = xchacha(key);
    let xnonce = XNonce::try_from(nonce.as_slice()).expect("object nonce is 24 bytes");
    let mut buffer = Vec::with_capacity(plaintext.len() + TAG_LEN);
    buffer.extend_from_slice(plaintext);
    if cipher.encrypt_in_place(&xnonce, aad, &mut buffer).is_err() {
        buffer.zeroize();
        return Err(CryptoError::Unavailable);
    }
    if !(MIN_OBJECT_CIPHERTEXT_LEN..=MAX_OBJECT_CIPHERTEXT_LEN).contains(&buffer.len()) {
        buffer.zeroize();
        return Err(CryptoError::Unavailable);
    }
    Ok(EncryptedObject {
        nonce: *nonce,
        ciphertext_and_tag: buffer,
    })
}

fn open_plaintext(
    key: &ObjectKey,
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if !(MIN_OBJECT_CIPHERTEXT_LEN..=MAX_OBJECT_CIPHERTEXT_LEN).contains(&ciphertext_and_tag.len())
    {
        return Err(CryptoError::Unavailable);
    }
    let cipher = xchacha(key);
    let xnonce = XNonce::try_from(nonce.as_slice()).expect("object nonce is 24 bytes");
    let mut buffer = Vec::from(ciphertext_and_tag);
    if cipher.decrypt_in_place(&xnonce, aad, &mut buffer).is_err() {
        buffer.zeroize();
        return Err(CryptoError::Unavailable);
    }
    if !(MIN_OBJECT_PLAINTEXT_LEN..=MAX_OBJECT_PLAINTEXT_LEN).contains(&buffer.len()) {
        buffer.zeroize();
        return Err(CryptoError::Unavailable);
    }
    Ok(buffer)
}

fn xchacha(key: &ObjectKey) -> XChaCha20Poly1305 {
    let key = Key::try_from(key.as_bytes().as_slice()).expect("object key is 32 bytes");
    XChaCha20Poly1305::new(&key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CryptoStatus, RootSecret, derive_object_key, status};
    use eidoron_test_vectors::key_schedule::{OBJECT_ID, OBJECT_KEY, ROOT_SECRET, VAULT_ID};
    use eidoron_test_vectors::object_aead::{AAD, CIPHERTEXT_AND_TAG, NONCE, PLAINTEXT};

    fn object_key() -> ObjectKey {
        let key = derive_object_key(&RootSecret::from_bytes(ROOT_SECRET), &VAULT_ID, &OBJECT_ID);
        assert_eq!(key.as_bytes(), &OBJECT_KEY);
        key
    }

    #[test]
    fn synthetic_object_matches_independent_oracle() {
        let key = object_key();
        let sealed = seal_authenticated(&key, &NONCE, &AAD, &PLAINTEXT).expect("seal");
        assert_eq!(sealed.nonce, NONCE);
        assert_eq!(sealed.ciphertext_and_tag, CIPHERTEXT_AND_TAG);
        let opened = decrypt_authenticated(&key, &NONCE, &AAD, &CIPHERTEXT_AND_TAG).expect("open");
        assert_eq!(opened, PLAINTEXT);
    }

    #[test]
    fn authentication_failures_are_the_same_unavailable_error() {
        let key = object_key();
        let wrong_key =
            derive_object_key(&RootSecret::from_bytes([0x43; 32]), &VAULT_ID, &OBJECT_ID);
        let wrong_key_error =
            decrypt_authenticated(&wrong_key, &NONCE, &AAD, &CIPHERTEXT_AND_TAG).unwrap_err();

        let mut flipped_aad = AAD;
        flipped_aad[0] ^= 0x01;
        let wrong_aad =
            decrypt_authenticated(&key, &NONCE, &flipped_aad, &CIPHERTEXT_AND_TAG).unwrap_err();

        let mut flipped_ciphertext = CIPHERTEXT_AND_TAG;
        flipped_ciphertext[0] ^= 0x01;
        let wrong_ciphertext =
            decrypt_authenticated(&key, &NONCE, &AAD, &flipped_ciphertext).unwrap_err();

        let mut flipped_tag = CIPHERTEXT_AND_TAG;
        let last = flipped_tag.len() - 1;
        flipped_tag[last] ^= 0x01;
        let wrong_tag = decrypt_authenticated(&key, &NONCE, &AAD, &flipped_tag).unwrap_err();

        let truncated = decrypt_authenticated(
            &key,
            &NONCE,
            &AAD,
            &CIPHERTEXT_AND_TAG[..CIPHERTEXT_AND_TAG.len() - 1],
        )
        .unwrap_err();
        let short = decrypt_authenticated(&key, &NONCE, &AAD, &[0u8; 17]).unwrap_err();
        let empty = decrypt_authenticated(&key, &NONCE, &AAD, &[]).unwrap_err();

        assert_eq!(wrong_key_error, CryptoError::Unavailable);
        assert_eq!(wrong_key_error, wrong_aad);
        assert_eq!(wrong_key_error, wrong_ciphertext);
        assert_eq!(wrong_key_error, wrong_tag);
        assert_eq!(wrong_key_error, truncated);
        assert_eq!(wrong_key_error, short);
        assert_eq!(wrong_key_error, empty);
        let rendered = format!("{wrong_key_error} {wrong_key_error:?}");
        assert_eq!(rendered, "unavailable Unavailable");
        assert!(!rendered.contains("synthetic"));
        assert!(!rendered.contains(&format!("{:02x}", OBJECT_KEY[0])));
    }

    #[test]
    fn plaintext_bounds_reject_before_aead() {
        let key = object_key();
        assert!(matches!(
            seal_authenticated(&key, &NONCE, &AAD, &[]),
            Err(CryptoError::UnsupportedParameters)
        ));
        assert!(matches!(
            seal_authenticated(&key, &NONCE, &AAD, &[0x01]),
            Err(CryptoError::UnsupportedParameters)
        ));
        let mut too_long = vec![0x04, 0x00];
        too_long.resize(MAX_OBJECT_PLAINTEXT_LEN + 1, 0);
        assert!(matches!(
            seal_authenticated(&key, &NONCE, &AAD, &too_long),
            Err(CryptoError::UnsupportedParameters)
        ));
        let minimum = [0x01, 0x00];
        let sealed = seal_authenticated(&key, &NONCE, &AAD, &minimum).expect("two-byte body");
        assert_eq!(sealed.ciphertext_and_tag.len(), MIN_OBJECT_CIPHERTEXT_LEN);
        let opened = decrypt_authenticated(&key, &sealed.nonce, &AAD, &sealed.ciphertext_and_tag)
            .expect("open minimum");
        assert_eq!(opened, minimum);
    }

    #[test]
    fn sealing_the_same_plaintext_twice_uses_fresh_nonces() {
        assert_eq!(status(), CryptoStatus::NotImplemented);
        let key = object_key();
        let first = encrypt_authenticated(&key, &AAD, &PLAINTEXT).expect("first seal");
        let second = encrypt_authenticated(&key, &AAD, &PLAINTEXT).expect("second seal");
        assert_eq!(first.nonce.len(), 24);
        assert_eq!(second.nonce.len(), 24);
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext_and_tag, second.ciphertext_and_tag);
        assert_eq!(first.ciphertext_and_tag.len(), PLAINTEXT.len() + TAG_LEN);
        assert_eq!(second.ciphertext_and_tag.len(), PLAINTEXT.len() + TAG_LEN);
        let opened_first =
            decrypt_authenticated(&key, &first.nonce, &AAD, &first.ciphertext_and_tag)
                .expect("open first");
        let opened_second =
            decrypt_authenticated(&key, &second.nonce, &AAD, &second.ciphertext_and_tag)
                .expect("open second");
        assert_eq!(opened_first, PLAINTEXT);
        assert_eq!(opened_second, PLAINTEXT);
    }
}
