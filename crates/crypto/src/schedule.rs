//! Vault v0 key schedule from the candidate envelope.
//!
//! `RawPwdKey` and `WrapKey` come from the passphrase. `ObjectKey` comes from
//! a separate `RootSecret`. None of these types print their bytes in `Debug`.

use std::fmt;

use argon2::{Algorithm, Argon2, ParamsBuilder, Version};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::CryptoError;

const PASSWORD_WRAP_LABEL: &[u8] = b"eidoron/v0/password-wrap";
const OBJECT_AEAD_LABEL: &[u8] = b"eidoron/v0/object-aead";
const MIN_MEMORY_KIB: u32 = 65_536;
const MAX_MEMORY_KIB: u32 = 262_144;
const MAX_ITERATIONS: u32 = 10;
const MAX_LANES: u32 = 4;
const MAX_PASSPHRASE_UTF8: usize = 1024;

/// Argon2id parameters. Memory is in kibibytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
}

impl fmt::Debug for KdfParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KdfParams")
            .field("memory_kib", &self.memory_kib)
            .field("iterations", &self.iterations)
            .field("lanes", &self.lanes)
            .finish()
    }
}

/// 32-byte Argon2id output. Not a vault root and not an AEAD key.
pub struct RawPwdKey([u8; 32]);

/// 32-byte key that wraps `RootSecret`.
pub struct WrapKey([u8; 32]);

/// 32-byte per-object AEAD key.
pub struct ObjectKey([u8; 32]);

/// 32-byte random vault root. Independent of the passphrase.
pub struct RootSecret([u8; 32]);

/// Ciphertext length of a wrapped root: 32-byte secret plus a 16-byte tag.
pub const WRAPPED_ROOT_LEN: usize = 48;

macro_rules! secret_bytes {
    ($name:ident) => {
        impl $name {
            /// Borrow the key bytes. `Debug` does not show them.
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(redacted)"))
            }
        }
    };
}

secret_bytes!(RawPwdKey);
secret_bytes!(WrapKey);
secret_bytes!(ObjectKey);
secret_bytes!(RootSecret);

/// `[u8; 32]` is `Copy`, so wipe the parameter after the owned copy is taken.
fn take_secret(mut bytes: [u8; 32]) -> [u8; 32] {
    let owned = bytes;
    bytes.zeroize();
    owned
}

impl RawPwdKey {
    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(take_secret(bytes))
    }
}

impl WrapKey {
    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(take_secret(bytes))
    }
}

impl ObjectKey {
    fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(take_secret(bytes))
    }
}

impl RootSecret {
    /// Take ownership of an already generated 32-byte root.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(take_secret(bytes))
    }
}

/// `RawPwdKey = Argon2id(utf-8 passphrase, salt, params, output_len=32, version=0x13)`.
///
/// The UTF-8 bytes are used as given. This function does not trim, case-fold,
/// or normalize. An empty passphrase, a passphrase over 1024 bytes, or
/// parameters outside the candidate bounds are rejected before Argon2 runs.
pub fn derive_raw_pwd_key(
    passphrase: &str,
    salt: &[u8; 16],
    params: KdfParams,
) -> Result<RawPwdKey, CryptoError> {
    let password = passphrase.as_bytes();
    if password.is_empty() || password.len() > MAX_PASSPHRASE_UTF8 || !params.allowed() {
        return Err(CryptoError::UnsupportedParameters);
    }
    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(params.memory_kib)
        .t_cost(params.iterations)
        .p_cost(params.lanes)
        .output_len(32);
    let built = builder
        .build()
        .map_err(|_| CryptoError::UnsupportedParameters)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, built);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| CryptoError::Unavailable)?;
    let key = RawPwdKey::from_bytes(out);
    out.zeroize();
    Ok(key)
}

/// `WrapKey = HKDF-Expand(HKDF-Extract(salt=vault_id, IKM=RawPwdKey), "eidoron/v0/password-wrap" || vault_id, 32)`.
pub fn derive_wrap_key(raw_pwd_key: &RawPwdKey, vault_id: &[u8; 16]) -> WrapKey {
    WrapKey::from_bytes(hkdf_32(
        raw_pwd_key.as_bytes(),
        vault_id,
        PASSWORD_WRAP_LABEL,
        vault_id,
    ))
}

/// `ObjectKey = HKDF-Expand(HKDF-Extract(salt=vault_id, IKM=RootSecret), "eidoron/v0/object-aead" || object_id, 32)`.
pub fn derive_object_key(
    root: &RootSecret,
    vault_id: &[u8; 16],
    object_id: &[u8; 32],
) -> ObjectKey {
    ObjectKey::from_bytes(hkdf_32(
        root.as_bytes(),
        vault_id,
        OBJECT_AEAD_LABEL,
        object_id,
    ))
}

/// Encrypt `RootSecret` under `WrapKey`. The result is ciphertext followed by the tag.
pub fn seal_root(
    wrap_key: &WrapKey,
    nonce: &[u8; 24],
    root: &RootSecret,
    aad: &[u8],
) -> [u8; WRAPPED_ROOT_LEN] {
    let cipher = xchacha(wrap_key.as_bytes());
    let xnonce = XNonce::try_from(nonce.as_slice()).expect("wrap nonce is 24 bytes");
    let sealed = cipher
        .encrypt(
            &xnonce,
            Payload {
                msg: root.as_bytes().as_slice(),
                aad,
            },
        )
        .expect("sealing a 32-byte root succeeds");
    let mut out = [0u8; WRAPPED_ROOT_LEN];
    out.copy_from_slice(&sealed);
    out
}

/// Decrypt a wrapped root.
///
/// A wrong key, a changed AAD, a changed tag, and a truncated wrapper all
/// return [`CryptoError::Unavailable`]. The error value does not carry key or
/// root bytes.
pub fn open_root(
    wrap_key: &WrapKey,
    nonce: &[u8; 24],
    wrapped: &[u8],
    aad: &[u8],
) -> Result<RootSecret, CryptoError> {
    if wrapped.len() != WRAPPED_ROOT_LEN {
        return Err(CryptoError::Unavailable);
    }
    let cipher = xchacha(wrap_key.as_bytes());
    let xnonce = XNonce::try_from(nonce.as_slice()).expect("wrap nonce is 24 bytes");
    let mut opened = cipher
        .decrypt(&xnonce, Payload { msg: wrapped, aad })
        .map_err(|_| CryptoError::Unavailable)?;
    if opened.len() != 32 {
        opened.zeroize();
        return Err(CryptoError::Unavailable);
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&opened);
    opened.zeroize();
    Ok(RootSecret::from_bytes(bytes))
}

impl KdfParams {
    fn allowed(self) -> bool {
        (MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib)
            && (1..=MAX_ITERATIONS).contains(&self.iterations)
            && (1..=MAX_LANES).contains(&self.lanes)
            && self.memory_kib >= 8 * self.lanes
    }
}

fn hkdf_32(ikm: &[u8], salt: &[u8; 16], label: &[u8], tail: &[u8]) -> [u8; 32] {
    let (_, hk) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), ikm);
    let mut info = Vec::with_capacity(label.len() + tail.len());
    info.extend_from_slice(label);
    info.extend_from_slice(tail);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .expect("32-byte hkdf output is within the sha-256 limit");
    out
}

fn xchacha(key: &[u8; 32]) -> XChaCha20Poly1305 {
    let key = Key::try_from(key.as_slice()).expect("wrap key is 32 bytes");
    XChaCha20Poly1305::new(&key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eidoron_test_vectors::key_schedule::{
        ITERATIONS, LANES, MEMORY_KIB, OBJECT_ID, OBJECT_KEY, OTHER_PASSPHRASE, PASSPHRASE,
        RAW_PWD_KEY, ROOT_SECRET, SALT, VAULT_ID, WRAP_KEY, WRAPPED_ROOT,
    };
    use eidoron_test_vectors::synthetic_untrusted_header;

    fn profile() -> KdfParams {
        KdfParams {
            memory_kib: MEMORY_KIB,
            iterations: ITERATIONS,
            lanes: LANES,
        }
    }

    fn aad() -> [u8; 88] {
        let header = synthetic_untrusted_header();
        header[0..88].try_into().expect("header prefix is 88 bytes")
    }

    #[test]
    fn synthetic_schedule_matches_independent_oracle() {
        let raw = derive_raw_pwd_key(PASSPHRASE, &SALT, profile()).expect("synthetic passphrase");
        assert_eq!(raw.as_bytes(), &RAW_PWD_KEY);
        assert_eq!(format!("{raw:?}"), "RawPwdKey(redacted)");

        let wrap = derive_wrap_key(&raw, &VAULT_ID);
        assert_eq!(wrap.as_bytes(), &WRAP_KEY);
        assert_eq!(format!("{wrap:?}"), "WrapKey(redacted)");

        let root = RootSecret::from_bytes(ROOT_SECRET);
        let object = derive_object_key(&root, &VAULT_ID, &OBJECT_ID);
        assert_eq!(object.as_bytes(), &OBJECT_KEY);
        assert_eq!(format!("{object:?}"), "ObjectKey(redacted)");
        assert_eq!(format!("{root:?}"), "RootSecret(redacted)");

        let aad = aad();
        let nonce: [u8; 24] = aad[64..88].try_into().expect("nonce is 24 bytes");
        let sealed = seal_root(&wrap, &nonce, &root, &aad);
        assert_eq!(sealed, WRAPPED_ROOT);
        let opened = open_root(&wrap, &nonce, &sealed, &aad).expect("open wrapped root");
        assert_eq!(opened.as_bytes(), &ROOT_SECRET);
    }

    #[test]
    fn unwrap_failures_are_the_same_unavailable_error() {
        let raw = derive_raw_pwd_key(PASSPHRASE, &SALT, profile()).expect("synthetic passphrase");
        let wrap = derive_wrap_key(&raw, &VAULT_ID);
        let root = RootSecret::from_bytes(ROOT_SECRET);
        let aad = aad();
        let nonce: [u8; 24] = aad[64..88].try_into().expect("nonce is 24 bytes");
        let sealed = seal_root(&wrap, &nonce, &root, &aad);

        let other =
            derive_raw_pwd_key(OTHER_PASSPHRASE, &SALT, profile()).expect("other passphrase");
        let other_wrap = derive_wrap_key(&other, &VAULT_ID);
        let wrong_password = open_root(&other_wrap, &nonce, &sealed, &aad).unwrap_err();

        let mut flipped_aad = aad;
        flipped_aad[0] ^= 0x01;
        let wrong_aad = open_root(&wrap, &nonce, &sealed, &flipped_aad).unwrap_err();

        let mut flipped_tag = sealed;
        flipped_tag[WRAPPED_ROOT_LEN - 1] ^= 0x01;
        let wrong_tag = open_root(&wrap, &nonce, &flipped_tag, &aad).unwrap_err();

        assert_eq!(wrong_password, CryptoError::Unavailable);
        assert_eq!(wrong_password, wrong_aad);
        assert_eq!(wrong_password, wrong_tag);
        assert_eq!(wrong_password.to_string(), "unavailable");
        assert_eq!(format!("{wrong_password:?}"), "Unavailable");
        let rendered = format!("{wrong_password} {wrong_password:?}");
        assert!(!rendered.contains(&hex_byte(ROOT_SECRET[0])));
        assert!(!rendered.contains(&hex_byte(WRAP_KEY[0])));
    }

    #[test]
    fn passphrase_and_parameter_limits_reject_before_derivation() {
        let salt = SALT;
        assert!(matches!(
            derive_raw_pwd_key("", &salt, profile()),
            Err(CryptoError::UnsupportedParameters)
        ));
        let too_long = "a".repeat(MAX_PASSPHRASE_UTF8 + 1);
        assert!(matches!(
            derive_raw_pwd_key(&too_long, &salt, profile()),
            Err(CryptoError::UnsupportedParameters)
        ));
        let mut low_memory = profile();
        low_memory.memory_kib = MIN_MEMORY_KIB - 1;
        assert!(matches!(
            derive_raw_pwd_key(PASSPHRASE, &salt, low_memory),
            Err(CryptoError::UnsupportedParameters)
        ));
    }

    fn hex_byte(byte: u8) -> String {
        format!("{byte:02x}")
    }
}
