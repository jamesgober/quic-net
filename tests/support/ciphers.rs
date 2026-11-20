//! Ciphers for tests, benches, and fuzzing: AES-128-GCM and
//! ChaCha20-Poly1305 behind quic-net's key traits. The library has no
//! cipher of its own; a TLS session provides its keys.

#![allow(dead_code)]

use aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Nonce, Tag};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20poly1305::ChaCha20Poly1305;
use quic_net::{
    AeadLimits, CryptoError, HeaderKey, KeyMaterial, PacketKey, RETRY_KEY_V1, RETRY_NONCE_V1,
    RetryIntegrity,
};

enum Aead {
    Aes(Box<Aes128Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

/// An AEAD key with its IV.
pub struct Key {
    aead: Aead,
    iv: [u8; 12],
}

/// A header protection key.
pub enum Hp {
    Aes(Box<aes::Aes128>),
    ChaCha([u8; 32]),
}

impl Key {
    /// AES-128-GCM from 16-byte key material.
    pub fn aes(m: &KeyMaterial) -> Key {
        Key {
            aead: Aead::Aes(Box::new(
                Aes128Gcm::new_from_slice(m.key()).expect("16-byte key"),
            )),
            iv: *m.iv(),
        }
    }

    /// ChaCha20-Poly1305 from 32-byte key material.
    pub fn chacha(m: &KeyMaterial) -> Key {
        Key {
            aead: Aead::ChaCha(Box::new(
                ChaCha20Poly1305::new_from_slice(m.key()).expect("32-byte key"),
            )),
            iv: *m.iv(),
        }
    }
}

impl Hp {
    /// AES-ECB from 16-byte key material.
    pub fn aes(m: &KeyMaterial) -> Hp {
        Hp::Aes(Box::new(
            aes::Aes128::new_from_slice(m.hp()).expect("16-byte key"),
        ))
    }

    /// ChaCha20 from 32-byte key material.
    pub fn chacha(m: &KeyMaterial) -> Hp {
        Hp::ChaCha(m.hp().try_into().expect("32-byte key"))
    }
}

impl PacketKey for Key {
    fn seal(&self, pn: u64, header: &[u8], payload: &mut [u8]) -> Result<[u8; 16], CryptoError> {
        let n = quic_net::nonce(&self.iv, pn);
        let nonce = Nonce::from_slice(&n);
        let tag = match &self.aead {
            Aead::Aes(a) => a.encrypt_in_place_detached(nonce, header, payload),
            Aead::ChaCha(a) => a.encrypt_in_place_detached(nonce, header, payload),
        }
        .map_err(|_| CryptoError)?;
        Ok(tag.into())
    }

    fn open(
        &self,
        pn: u64,
        header: &[u8],
        payload: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), CryptoError> {
        let n = quic_net::nonce(&self.iv, pn);
        let nonce = Nonce::from_slice(&n);
        let tag = Tag::from_slice(tag);
        match &self.aead {
            Aead::Aes(a) => a.decrypt_in_place_detached(nonce, header, payload, tag),
            Aead::ChaCha(a) => a.decrypt_in_place_detached(nonce, header, payload, tag),
        }
        .map_err(|_| CryptoError)
    }

    fn limits(&self) -> AeadLimits {
        match self.aead {
            Aead::Aes(_) => AeadLimits::AES_GCM,
            Aead::ChaCha(_) => AeadLimits::CHACHA20_POLY1305,
        }
    }
}

impl HeaderKey for Hp {
    fn mask(&self, sample: &[u8; 16]) -> Result<[u8; 5], CryptoError> {
        let mut m = [0u8; 5];
        match self {
            Hp::Aes(c) => {
                let mut block = (*sample).into();
                c.encrypt_block(&mut block);
                m.copy_from_slice(&block[..5]);
            }
            Hp::ChaCha(key) => {
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                let mut c = ChaCha20::new(key.into(), sample[4..].into());
                c.seek(u64::from(counter) * 64);
                c.apply_keystream(&mut m);
            }
        }
        Ok(m)
    }
}

/// The Retry integrity AEAD.
pub struct Retry(Aes128Gcm);

impl Retry {
    pub fn new() -> Retry {
        Retry(Aes128Gcm::new_from_slice(&RETRY_KEY_V1).expect("16-byte key"))
    }
}

impl RetryIntegrity for Retry {
    fn tag(&self, pseudo_packet: &[u8]) -> Result<[u8; 16], CryptoError> {
        let tag = self
            .0
            .encrypt_in_place_detached(Nonce::from_slice(&RETRY_NONCE_V1), pseudo_packet, &mut [])
            .map_err(|_| CryptoError)?;
        Ok(tag.into())
    }
}
