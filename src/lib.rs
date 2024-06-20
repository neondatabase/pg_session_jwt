use std::cell::RefCell;
use std::io::Cursor;

use base64::engine::general_purpose;
use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::elliptic_curve::generic_array::GenericArray;
use p256::PublicKey;
use pg_sys::pid_t;
use pgrx::{prelude::*, JsonB};

pgrx::pg_module_magic!();

thread_local! {
    static JWK: RefCell<Option<(pid_t, VerifyingKey)>> = const { RefCell::new(None) };
    static JWT: RefCell<serde_json::Value> = const { RefCell::new(serde_json::Value::Null) };
    static TXID: RefCell<i64> = const { RefCell::new(0) };
}

#[pg_extern]
fn init_jwk(pid: pid_t, s: &str) {
    JWK.with_borrow_mut(|k| {
        if k.is_some() {
            panic!("JWK state can only be set once per session.")
        }

        let key = PublicKey::from_jwk_str(s).unwrap();
        let key = VerifyingKey::from(key);
        *k = Some((pid, key));
    });
}

#[pg_extern]
fn decrypt_jwt(s: &str) {
    let (pid, key) = JWK.with_borrow(|b| b.unwrap());
    let (header_payload, sig) = s.rsplit_once('.').unwrap();

    let mut sig_bytes = GenericArray::default();
    Base64UrlUnpadded::decode(sig, &mut sig_bytes).unwrap();
    let sig = Signature::from_bytes(&sig_bytes).unwrap();

    key.verify(header_payload.as_bytes(), &sig).unwrap();

    let (header, payload) = header_payload.split_once('.').unwrap();
    let header: serde_json::Value = json_base64_decode(header);
    let payload: serde_json::Value = json_base64_decode(payload);

    let header = header.as_object().expect("JWT header must be an object");
    let pid2 = header["pid"]
        .as_number()
        .expect("JWT header must contain a valid PID")
        .as_i64()
        .expect("JWT header must contain a valid PID");
    if pid as i64 != pid2 {
        panic!("PID mismatch");
    }

    let txid = header["txid"]
        .as_number()
        .expect("JWT header must contain a valid TXID")
        .as_i64()
        .expect("JWT header must contain a valid TXID");
    TXID.with_borrow_mut(|t| {
        if txid <= *t {
            panic!("TXID not monotonic");
        }
        *t = txid;
    });

    assert!(payload.is_object(), "JWT payload must be an object");
    JWT.set(payload);
}

#[pg_extern]
fn neon_get(s: &str) -> JsonB {
    JWT.with_borrow(|j| {
        if j.is_null() {
            JsonB(serde_json::Value::Null)
        } else {
            JsonB(j[s].clone())
        }
    })
}

fn json_base64_decode(s: &str) -> serde_json::Value {
    let mut r = Cursor::new(s.as_bytes());
    let r = base64::read::DecoderReader::new(&mut r, &general_purpose::URL_SAFE_NO_PAD);
    serde_json::from_reader(r).unwrap()
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use base64::engine::general_purpose;
    use base64::Engine;
    use p256::ecdsa::signature::Signer;
    use p256::{
        ecdsa::{Signature, SigningKey},
        elliptic_curve::JwkEcKey,
    };
    use p256::{NistP256, PublicKey};
    use pgrx::prelude::*;
    use rand::rngs::OsRng;
    use serde_json::json;

    fn encode_str(s: impl AsRef<[u8]>) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(s)
    }

    fn sign_jwt(sk: &SigningKey, header: &str, payload: &str) -> String {
        let header = encode_str(header);
        let payload = encode_str(payload);

        let message = format!("{header}.{payload}");
        let sig: Signature = sk.sign(message.as_bytes());
        let base64_sig = encode_str(sig.to_bytes());
        format!("{message}.{base64_sig}")
    }

    #[pg_test]
    #[should_panic = "JWK state can only be set once per session."]
    fn init_jwk_twice() {
        let sk = SigningKey::random(&mut OsRng);
        let point = sk.verifying_key().to_encoded_point(false);
        let jwk = JwkEcKey::from_encoded_point::<NistP256>(&point).unwrap();
        let jwk = serde_json::to_string(&jwk).unwrap();

        crate::init_jwk(1, &jwk);
        crate::init_jwk(2, &jwk);
    }

    #[pg_test]
    #[should_panic = "PID mismatch"]
    fn wrong_pid() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk_string();

        crate::init_jwk(1, &jwk);
        crate::decrypt_jwt(&sign_jwt(&sk, r#"{"pid":2,"txid":1}"#, r#"{}"#));
    }

    #[pg_test]
    #[should_panic = "TXID not monotonic"]
    fn wrong_txid() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk_string();

        crate::init_jwk(1, &jwk);
        crate::decrypt_jwt(&sign_jwt(&sk, r#"{"pid":1,"txid":2}"#, r#"{}"#));
        crate::decrypt_jwt(&sign_jwt(&sk, r#"{"pid":1,"txid":1}"#, r#"{}"#));
    }

    #[pg_test]
    fn test_neon_jwt() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk_string();

        crate::init_jwk(1, &jwk);
        crate::decrypt_jwt(&sign_jwt(
            &sk,
            r#"{"pid":1,"txid":1}"#,
            r#"{"sub":"conradludgate"}"#,
        ));
        assert_eq!(crate::neon_get("sub").0, json!("conradludgate"));

        crate::decrypt_jwt(&sign_jwt(
            &sk,
            r#"{"pid":1,"txid":2}"#,
            r#"{"sub":"not_conradludgate"}"#,
        ));
        assert_eq!(crate::neon_get("sub").0, json!("not_conradludgate"));
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
