use std::cell::{OnceCell, RefCell};
use std::io::Cursor;

use base64::engine::general_purpose;
use base64ct::{Base64UrlUnpadded, Encoding};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::elliptic_curve::generic_array::GenericArray;
use p256::PublicKey;
use pgrx::{prelude::*, JsonB};
use serde::de::DeserializeOwned;

type Object = serde_json::Map<String, serde_json::Value>;

pgrx::pg_module_magic!();

thread_local! {
    static JWK: OnceCell<Key> = const { OnceCell::new() };
    static JWT: RefCell<Option<Object>> = const { RefCell::new(None) };
    static JTI: RefCell<i64> = const { RefCell::new(0) };
}

#[derive(Clone)]
struct Key {
    kid: i64,
    key: VerifyingKey,
}

#[pg_extern]
fn jwk_init(kid: i64, s: &str) {
    let key = PublicKey::from_jwk_str(s).unwrap();
    let key = VerifyingKey::from(key);
    JWK.with(|j| {
        if j.set(Key { kid, key }).is_err() {
            panic!("JWK state can only be set once per session.")
        }
    })
}

fn verify_signature(key: &Key, body: &str, sig: &str) {
    let mut sig_bytes = GenericArray::default();
    Base64UrlUnpadded::decode(sig, &mut sig_bytes).unwrap();
    let sig = Signature::from_bytes(&sig_bytes).unwrap();

    key.key.verify(body.as_bytes(), &sig).unwrap();
}

fn verify_key_id(key: &Key, header: &Object) {
    let kid = header["kid"]
        .as_i64()
        .expect("JWT header must contain a valid 'kid' (key ID)");
    if key.kid != kid {
        panic!("Key ID mismatch");
    }
}

fn verify_token_id(payload: &Object) -> i64 {
    let jti = payload["jti"]
        .as_i64()
        .expect("JWT payload must contain a valid 'jti' (JWT ID)");

    JTI.with_borrow(|t| {
        if jti <= *t {
            panic!("Token ID must be strictly monotonically increasing.");
        }
    });

    jti
}

fn verify_time(payload: &Object) {
    let now = now()
        .to_utc()
        .extract_part(DateTimeParts::Epoch)
        .expect("could not get current unix epoch");
    if let Some(nbf) = payload.get("nbf") {
        let nbf = nbf
            .as_i64()
            .expect("'nbf' (Not Before) must be an integer representing seconds since unix epoch");
        let nbf = AnyNumeric::from(nbf);
        assert!(nbf < now, "Token used before it is ready")
    }
    if let Some(exp) = payload.get("exp") {
        let exp = exp
            .as_i64()
            .expect("'exp' (Expiration) must be an integer representing seconds since unix epoch");
        let exp = AnyNumeric::from(exp);
        assert!(now < exp, "Token used after it has expired")
    }
}

#[pg_extern]
fn jwt_session_init(s: &str) {
    let key = JWK.with(|b| b.get().expect("JWK state has not been initialised").clone());
    let (body, sig) = s.rsplit_once('.').unwrap();
    let (header, payload) = body.split_once('.').unwrap();
    let header: Object = json_base64_decode(header);

    verify_key_id(&key, &header);
    verify_signature(&key, body, sig);

    let payload: Object = json_base64_decode(payload);
    let jti = verify_token_id(&payload);
    verify_time(&payload);

    // update state
    JTI.replace(jti);
    JWT.set(Some(payload));
}

#[pg_extern]
fn user_extract(s: &str) -> JsonB {
    JWT.with_borrow(|j| {
        if let Some(j) = j {
            JsonB(j[s].clone())
        } else {
            JsonB(serde_json::Value::Null)
        }
    })
}

#[pg_extern]
fn user_id() -> String {
    match user_extract("sub").0 {
        serde_json::Value::String(s) => s,
        _ => panic!("invalid subject claim in the JWT"),
    }
}

fn json_base64_decode<D: DeserializeOwned>(s: &str) -> D {
    let mut r = Cursor::new(s.as_bytes());
    let r = base64::read::DecoderReader::new(&mut r, &general_purpose::URL_SAFE_NO_PAD);
    serde_json::from_reader(r).unwrap()
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use std::fmt::Display;
    use std::time::{SystemTime, UNIX_EPOCH};

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

    fn sign_jwt(sk: &SigningKey, header: &str, payload: impl Display) -> String {
        let header = encode_str(header);
        let payload = encode_str(payload.to_string());

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

        crate::jwk_init(1, &jwk);
        crate::jwk_init(2, &jwk);
    }

    #[pg_test]
    #[should_panic = "Key ID mismatch"]
    fn wrong_pid() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk_string();

        crate::jwk_init(1, &jwk);
        crate::jwt_session_init(&sign_jwt(&sk, r#"{"kid":2}"#, r#"{"jti":1}"#));
    }

    #[pg_test]
    #[should_panic = "Token ID must be strictly monotonically increasing"]
    fn wrong_txid() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk_string();

        crate::jwk_init(1, &jwk);
        crate::jwt_session_init(&sign_jwt(&sk, r#"{"kid":1}"#, r#"{"jti":2}"#));
        crate::jwt_session_init(&sign_jwt(&sk, r#"{"kid":1}"#, r#"{"jti":1}"#));
    }

    #[pg_test]
    #[should_panic = "Token used before it is ready"]
    fn invalid_nbf() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk_string();

        crate::jwk_init(1, &jwk);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        crate::jwt_session_init(&sign_jwt(
            &sk,
            r#"{"kid":1}"#,
            json!({"jti": 1, "nbf": now + 10}),
        ));
    }

    #[pg_test]
    #[should_panic = "Token used after it has expired"]
    fn invalid_exp() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk_string();

        crate::jwk_init(1, &jwk);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        crate::jwt_session_init(&sign_jwt(
            &sk,
            r#"{"kid":1}"#,
            json!({"jti": 1, "nbf": now - 10, "exp": now - 5}),
        ));
    }

    #[pg_test]
    fn valid_time() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk_string();

        crate::jwk_init(1, &jwk);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let header = r#"{"kid":1}"#;

        crate::jwt_session_init(&sign_jwt(
            &sk,
            header,
            json!({"jti": 1, "nbf": now - 10, "exp": now + 10}),
        ));
        crate::jwt_session_init(&sign_jwt(&sk, header, json!({"jti": 2, "nbf": now - 10})));
        crate::jwt_session_init(&sign_jwt(&sk, header, json!({"jti": 3, "exp": now + 10})));
    }

    #[pg_test]
    fn test_neon_jwt() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk_string();

        crate::jwk_init(1, &jwk);
        let header = r#"{"kid":1}"#;

        crate::jwt_session_init(&sign_jwt(&sk, header, r#"{"sub":"foo","jti":1}"#));
        assert_eq!(crate::user_extract("sub").0, json!("foo"));

        crate::jwt_session_init(&sign_jwt(&sk, header, r#"{"sub":"bar","jti":2}"#));
        assert_eq!(crate::user_extract("sub").0, json!("bar"));
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
