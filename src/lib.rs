use std::cell::RefCell;
use std::io::Cursor;

use base64::engine::general_purpose;
use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{AffinePoint, EncodedPoint, FieldBytes};
use pg_sys::pid_t;
use pgrx::{prelude::*, JsonB};
use serde::Deserialize;

pgrx::pg_module_magic!();

thread_local! {
    static JWK: RefCell<Option<(pid_t, VerifyingKey)>> = const { RefCell::new(None) };
    static JWT: RefCell<JsonB> = const { RefCell::new(JsonB(serde_json::Value::Null)) };
    static TXID: RefCell<u64> = const { RefCell::new(0) };
}

#[pg_extern]
fn init_jwk(pid: pid_t, s: &str) {
    /// JSON Web Key (JWK) with a `kty` of `"EC"` (elliptic curve).
    ///
    /// Specified in [RFC 7518 Section 6: Cryptographic Algorithms for Keys][1].
    ///
    /// [1]: https://tools.ietf.org/html/rfc7518#section-6
    #[derive(Deserialize)]
    pub struct JwkEcKey<'a> {
        kty: &'a str,

        /// The `crv` parameter which identifies a particular elliptic curve
        /// as defined in RFC 7518 Section 6.2.1.1:
        /// <https://tools.ietf.org/html/rfc7518#section-6.2.1.1>
        crv: &'a str,

        /// The x-coordinate of the elliptic curve point which is the public key
        /// value associated with this JWK as defined in RFC 7518 6.2.1.2:
        /// <https://tools.ietf.org/html/rfc7518#section-6.2.1.2>
        x: &'a str,

        /// The y-coordinate of the elliptic curve point which is the public key
        /// value associated with this JWK as defined in RFC 7518 6.2.1.3:
        /// <https://tools.ietf.org/html/rfc7518#section-6.2.1.3>
        y: &'a str,
    }

    let key: JwkEcKey = serde_json::from_str(s).unwrap();
    assert_eq!(key.kty, "EC");
    assert_eq!(key.crv, "P-256");

    let point = EncodedPoint::from_affine_coordinates(
        &decode_base64url_fe(key.x),
        &decode_base64url_fe(key.y),
        false,
    );

    let point = AffinePoint::from_encoded_point(&point).unwrap();
    let key = VerifyingKey::from_affine(point).unwrap();
    JWK.with_borrow_mut(|k| {
        if k.is_some() {
            panic!("jwk already set")
        }
        *k = Some((pid, key));
    });
}

#[pg_extern]
fn decrypt_jwt(s: &str) {
    let (pid, key) = JWK.with_borrow(|b| b.unwrap());
    let (header_body, sig) = s.rsplit_once('.').unwrap();

    let mut sig_bytes = GenericArray::default();
    Base64UrlUnpadded::decode(sig, &mut sig_bytes).unwrap();
    let sig = Signature::from_bytes(&sig_bytes).unwrap();

    key.verify(header_body.as_bytes(), &sig).unwrap();

    let (header, body) = header_body.split_once('.').unwrap();
    let header: serde_json::Value = json_base64_decode(header);
    let body: serde_json::Value = json_base64_decode(body);

    assert_eq!(pid, header["pid"]);

    JWT.set(JsonB(body));
}

#[pg_extern]
fn neon_get(s: &str) -> JsonB {
    JWT.with_borrow(|j| {
        if j.0.is_null() {
            JsonB(serde_json::Value::Null)
        } else {
            JsonB(j.0[s].clone())
        }
    })
}

fn json_base64_decode(s: &str) -> serde_json::Value {
    let mut r = Cursor::new(s.as_bytes());
    let r = base64::read::DecoderReader::new(&mut r, &general_purpose::URL_SAFE_NO_PAD);
    serde_json::from_reader(r).unwrap()
}

/// Decode a Base64url-encoded field element
fn decode_base64url_fe(s: &str) -> FieldBytes {
    let mut result = FieldBytes::default();
    Base64UrlUnpadded::decode(s, &mut result).unwrap();
    result
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use p256::ecdsa::signature::Signer;
    use p256::NistP256;
    use p256::{
        ecdsa::{Signature, SigningKey},
        elliptic_curve::JwkEcKey,
    };
    use pgrx::prelude::*;
    use rand::rngs::OsRng;
    use serde_json::json;

    #[pg_test]
    #[should_panic]
    fn init_jwk_twice() {
        let sk = SigningKey::random(&mut OsRng);
        let point = sk.verifying_key().to_encoded_point(false);
        let jwk = JwkEcKey::from_encoded_point::<NistP256>(&point).unwrap();
        let jwk = serde_json::to_string(&jwk).unwrap();

        crate::init_jwk(1, &jwk);
        crate::init_jwk(2, &jwk);
    }

    #[pg_test]
    fn test_neon_jwt() {
        let sk = SigningKey::random(&mut OsRng);
        let point = sk.verifying_key().to_encoded_point(false);
        let jwk = JwkEcKey::from_encoded_point::<NistP256>(&point).unwrap();
        let jwk = serde_json::to_string(&jwk).unwrap();

        let message = "eyJwaWQiOjEsInRpZCI6MX0.eyJzdWIiOiJjb25yYWRsdWRnYXRlIiwiYXVkIjoibmVvbiJ9";
        let sig: Signature = sk.sign(message.as_bytes());
        let base64_sig = Base64UrlUnpadded::encode_string(&sig.to_bytes());

        crate::init_jwk(1, &jwk);
        crate::decrypt_jwt(&format!("{message}.{base64_sig}"));
        assert_eq!(crate::neon_get("sub").0, json!("conradludgate"));
    }
}

/// This module is required by `cargo pgrx test` invocations.
/// It must be visible at the root of your extension crate.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}
