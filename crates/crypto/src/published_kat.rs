//! Published known-answer vectors. Expected bytes are transcribed from the
//! cited documents. They are not outputs of this crate.

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

fn decode_hex(input: &str) -> Vec<u8> {
    let compact: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let digits = compact
        .strip_prefix("0x")
        .or_else(|| compact.strip_prefix("0X"))
        .unwrap_or(compact.as_str());
    assert_eq!(digits.len() % 2, 0, "published hex length");
    (0..digits.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&digits[index..index + 2], 16).expect("published hex digit")
        })
        .collect()
}

/// RFC 9106 section 5.3, Argon2id version 19.
/// Password 32×`01`, salt 16×`02`, secret 8×`03`, associated data 12×`04`,
/// memory 32 KiB, 3 passes, 4 lanes, 32-byte tag.
#[test]
fn rfc9106_argon2id_section_5_3() {
    let password = [0x01u8; 32];
    let salt = [0x02u8; 16];
    let secret = [0x03u8; 8];
    let associated = [0x04u8; 12];
    // Tag printed in RFC 9106 section 5.3.
    let expected = decode_hex(
        "0d 64 0d f5 8d 78 76 6c 08 c0 37 a3 4a 8b 53 c9 d0
         1e f0 45 2d 75 b6 5e b5 25 20 e9 6b 01 e6 59",
    );

    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(AssociatedData::new(&associated).expect("rfc associated data"));
    let params = builder.build().expect("rfc 9106 parameters");
    let argon2 = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params)
        .expect("rfc 9106 secret");
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(&password, &salt, &mut out)
        .expect("argon2id hash");
    assert_eq!(out.as_slice(), expected.as_slice());
    out.zeroize();
    assert_eq!(out, [0u8; 32]);
}

/// RFC 5869 appendix A.1, test case 1, HKDF-SHA-256.
#[test]
fn rfc5869_hkdf_sha256_test_case_1() {
    let ikm = decode_hex("0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = decode_hex("0x000102030405060708090a0b0c");
    let info = decode_hex("0xf0f1f2f3f4f5f6f7f8f9");
    let expected_prk = decode_hex(
        "077709362c2e32df0ddc3f0dc47bba63
         90b6c73bb50f9c3122ec844ad7c2b3e5",
    );
    let expected_okm = decode_hex(
        "3cb25f25faacd57a90434f64d0362f2a
         2d2d0a90cf1a5a4c5db02d56ecc4c5bf
         34007208d5b887185865",
    );
    assert_eq!(ikm.len(), 22);
    assert_eq!(salt.len(), 13);
    assert_eq!(info.len(), 10);
    assert_eq!(expected_prk.len(), 32);
    assert_eq!(expected_okm.len(), 42);

    let (prk, hk) = Hkdf::<Sha256>::extract(Some(salt.as_slice()), &ikm);
    assert_eq!(&prk[..], expected_prk.as_slice());
    let mut okm = [0u8; 42];
    hk.expand(info.as_slice(), &mut okm)
        .expect("rfc 5869 expand length");
    assert_eq!(okm.as_slice(), expected_okm.as_slice());
    okm.zeroize();
    assert_eq!(okm, [0u8; 42]);
}

/// draft-irtf-cfrg-xchacha-03 appendix A.3.1, AEAD_XCHACHA20_POLY1305.
/// Key is 32 bytes, IV is 24 bytes, tag is 16 bytes.
#[test]
fn draft_irtf_cfrg_xchacha_03_aead_a_3_1() {
    let plaintext = decode_hex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c6173
         73206f66202739393a204966204920636f756c64206f6666657220796f75206f
         6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73
         637265656e20776f756c642062652069742e",
    );
    let aad = decode_hex("50515253c0c1c2c3c4c5c6c7");
    let key_bytes = decode_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let iv = decode_hex("404142434445464748494a4b4c4d4e4f5051525354555657");
    let expected_ciphertext = decode_hex(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
         731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
         2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
         21f9664c97637da9768812f615c68b13b52e",
    );
    let expected_tag = decode_hex("c0875924c1c7987947deafd8780acf49");
    assert_eq!(key_bytes.len(), 32);
    assert_eq!(iv.len(), 24);
    assert_eq!(expected_tag.len(), 16);
    assert_eq!(expected_ciphertext.len(), plaintext.len());

    let key = Key::try_from(key_bytes.as_slice()).expect("32-byte key");
    let nonce = XNonce::try_from(iv.as_slice()).expect("24-byte nonce");
    let cipher = XChaCha20Poly1305::new(&key);
    let mut combined = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .expect("xchacha20-poly1305 encrypt");
    assert_eq!(combined.len(), plaintext.len() + 16);
    assert_eq!(&combined[..plaintext.len()], expected_ciphertext.as_slice());
    assert_eq!(&combined[plaintext.len()..], expected_tag.as_slice());

    let opened = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: combined.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .expect("xchacha20-poly1305 decrypt");
    assert_eq!(opened, plaintext);
    combined.zeroize();
}
