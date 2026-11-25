//! tls-net's QUIC keys behind quic-net's key traits (PLAN D-017).

use crate::protect::{AeadLimits, CryptoError, HeaderKey, PacketKey, RetryIntegrity, TAG_LEN};

impl PacketKey for tls_net::quic::PacketKey {
    fn seal(
        &self,
        pn: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<[u8; TAG_LEN], CryptoError> {
        tls_net::quic::PacketKey::seal(self, pn, header, payload).map_err(|_| CryptoError)
    }

    fn open(
        &self,
        pn: u64,
        header: &[u8],
        payload_and_tag: &mut [u8],
    ) -> Result<usize, CryptoError> {
        tls_net::quic::PacketKey::open(self, pn, header, payload_and_tag).map_err(|_| CryptoError)
    }

    fn limits(&self) -> AeadLimits {
        AeadLimits {
            confidentiality: self.confidentiality_limit(),
            integrity: self.integrity_limit(),
        }
    }
}

impl HeaderKey for tls_net::quic::HeaderKey {
    fn mask(&self, sample: &[u8; 16]) -> Result<[u8; 5], CryptoError> {
        tls_net::quic::HeaderKey::mask(self, sample).map_err(|_| CryptoError)
    }
}

/// The Retry integrity tag through tls-net's provider.
///
/// ```
/// use quic_net::{ConnectionId, TlsRetry, retry_tag};
/// let odcid = ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08])?;
/// let tag = retry_tag(&odcid, b"a Retry packet without its tag", &TlsRetry)?;
/// assert_eq!(tag.len(), 16);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct TlsRetry;

impl RetryIntegrity for TlsRetry {
    fn tag(&self, pseudo_packet: &[u8]) -> Result<[u8; 16], CryptoError> {
        tls_net::quic::retry_tag(pseudo_packet).map_err(|_| CryptoError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnectionId, open_payload, remove_header_protection, retry_tag, verify_retry};

    fn h(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_rfc_9001_vectors_through_tls_net() {
        // A.4: the Retry tag.
        let odcid = ConnectionId::new(&h("8394c8f03e515708")).unwrap();
        let retry = h("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba");
        assert!(verify_retry(&odcid, &retry, &TlsRetry));
        let tag = retry_tag(&odcid, &retry[..retry.len() - 16], &TlsRetry).unwrap();
        assert_eq!(tag[..], retry[retry.len() - 16..]);
        // A.5's short header packet opens with A.1-style keys is covered in
        // tests/rfc9001.rs; here the Initial keys of A.1 open A.3's server
        // Initial.
        let packet_hex = concat!(
            "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a",
            "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3",
            "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84",
            "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4",
            "2158407dd074ee"
        );
        let mut packet = h(packet_hex);
        let keys =
            tls_net::quic::initial_keys(odcid.as_slice(), tls_net::quic::Side::Client).unwrap();
        let u = remove_header_protection(&mut packet, 18, None, &keys.remote.header).unwrap();
        assert_eq!(u.pn, 1);
        let r = open_payload(&mut packet, &u, &keys.remote.packet).unwrap();
        assert_eq!(&packet[r][..6], &h("020000000006")[..]);
    }
}
