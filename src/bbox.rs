//! Parser for the "bbox" identity blob format used by p-radar and friends.
//!
//! A bbox is a flat TLV stream: each record is `tag(1 byte) | len(2 bytes, big endian) | value`.
//! It carries a complete, already-registered IDS identity (push creds + IDS identity
//! cert/key), so it can be used for pure-HTTP `id-query` lookups without any
//! registration, anisette, validation data, or live APNs connection.

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD, Engine};
use keystore::{KeystoreAccessRules, KeystoreDigest, KeystorePadding, RsaKey};
use plist::Value;

use crate::util::KeyPairNew;
use crate::PushError;

// TLV tags. High nibble = category, low nibble = index within category.
const TAG_SERIAL: u8 = 0x10;
const TAG_MAIN_ID: u8 = 0x11;
const TAG_REG_PLIST: u8 = 0x13; // embedded registration response bplist
const TAG_PUSH_TOKEN: u8 = 0x21;
const TAG_ID_CERT: u8 = 0x31; // IDS identity cert (signs id-query)
const TAG_ID_PRIV_KEY: u8 = 0x32; // matching RSA-2048 private key (PKCS#1 DER)

/// A parsed bbox identity, holding everything needed for an `id-query` lookup.
#[derive(Debug, Clone)]
pub struct Bbox {
    pub serial: String,
    /// Primary registered alias (e.g. an email), informational.
    pub main_id: String,
    /// The `x-id-self-uri` to send (e.g. `mailto:foo@bar.com` or `tel:+1...`).
    pub self_uri: String,
    /// IDS service this identity is registered for (e.g. `com.apple.madrid`).
    pub service: String,
    pub push_token: [u8; 32],
    /// DER-encoded IDS identity certificate (`x-id-cert`).
    pub id_cert: Vec<u8>,
    /// PKCS#1 DER RSA private key matching `id_cert`.
    pub id_priv_der: Vec<u8>,
}

impl Bbox {
    /// Parse a base64-encoded bbox.
    pub fn parse_b64(b64: &str) -> Result<Self, PushError> {
        let data = STANDARD.decode(b64.trim()).map_err(|_| PushError::BadMsg)?;
        Self::parse(&data)
    }

    /// Parse a raw (already base64-decoded) bbox TLV stream.
    pub fn parse(data: &[u8]) -> Result<Self, PushError> {
        let mut tlv: HashMap<u8, Vec<u8>> = HashMap::new();
        let mut i = 0usize;
        while i + 3 <= data.len() {
            let tag = data[i];
            let len = u16::from_be_bytes([data[i + 1], data[i + 2]]) as usize;
            let start = i + 3;
            let end = start.checked_add(len).ok_or(PushError::BadMsg)?;
            if end > data.len() {
                return Err(PushError::BadMsg);
            }
            tlv.insert(tag, data[start..end].to_vec());
            i = end;
        }

        let serial = tlv
            .get(&TAG_SERIAL)
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default();
        let main_id = tlv
            .get(&TAG_MAIN_ID)
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default();

        let push_token: [u8; 32] = tlv
            .get(&TAG_PUSH_TOKEN)
            .ok_or(PushError::BadMsg)?
            .as_slice()
            .try_into()
            .map_err(|_| PushError::BadMsg)?;

        let id_cert = tlv.get(&TAG_ID_CERT).ok_or(PushError::BadMsg)?.clone();
        let id_priv_der = tlv.get(&TAG_ID_PRIV_KEY).ok_or(PushError::BadMsg)?.clone();

        // Default the self-uri from the main id; override from the embedded
        // registration plist when present (it carries the exact registered uri).
        let mut self_uri = if main_id.is_empty() {
            String::new()
        } else {
            format!("mailto:{main_id}")
        };
        let mut service = "com.apple.madrid".to_string();

        if let Some(reg) = tlv.get(&TAG_REG_PLIST) {
            if let Ok(value) = plist::from_bytes::<Value>(reg) {
                if let Some((uri, svc)) = extract_uri_service(&value) {
                    if let Some(uri) = uri {
                        self_uri = uri;
                    }
                    if let Some(svc) = svc {
                        service = svc;
                    }
                }
            }
        }

        if self_uri.is_empty() {
            return Err(PushError::BadMsg);
        }

        Ok(Bbox {
            serial,
            main_id,
            self_uri,
            service,
            push_token,
            id_cert,
            id_priv_der,
        })
    }

    /// Import the identity RSA key into the active keystore and pair it with the cert.
    /// The resulting keypair is what `id-query` is signed with (`KeyType::Id`).
    pub fn id_keypair(&self) -> Result<KeyPairNew<RsaKey>, PushError> {
        let alias = format!("bbox-id:{}", self.serial);
        let private = RsaKey::import(
            &alias,
            2048,
            &self.id_priv_der,
            KeystoreAccessRules {
                signature_padding: vec![KeystorePadding::PKCS1],
                digests: vec![KeystoreDigest::Sha1],
                can_sign: true,
                ..Default::default()
            },
        )?;
        Ok(KeyPairNew {
            cert: self.id_cert.clone(),
            private,
        })
    }
}

/// Pull the first registered uri and the service identifier out of the
/// embedded registration response plist (tag 0x13).
fn extract_uri_service(value: &Value) -> Option<(Option<String>, Option<String>)> {
    let root = value.as_dictionary()?;
    let data = root.get("data")?.as_array()?;
    let first = data.first()?.as_dictionary()?;

    let service = first
        .get("service-identifier")
        .and_then(|v| v.as_string())
        .map(|s| s.to_string());

    let uri = first.get("uris").and_then(|v| v.as_array()).and_then(|uris| {
        uris.first().and_then(|entry| match entry {
            Value::String(s) => Some(s.clone()),
            Value::Dictionary(d) => d.get("uri").and_then(|u| u.as_string()).map(|s| s.to_string()),
            _ => None,
        })
    });

    Some((uri, service))
}
