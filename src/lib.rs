use pgrx::prelude::*;

pgrx::pg_module_magic!();

#[pg_schema]
pub mod auth {
    use std::cell::{OnceCell, RefCell};

    use base64ct::{Base64UrlUnpadded, Decoder, Encoding};
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::elliptic_curve::generic_array::GenericArray;
    use p256::elliptic_curve::JwkEcKey;
    use p256::PublicKey;
    use pgrx::prelude::*;
    use pgrx::JsonB;
    use serde::de::DeserializeOwned;

    type Object = serde_json::Map<String, serde_json::Value>;

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

    /// Set the public key and key ID for this postgres session.
    ///
    /// # Panics
    ///
    /// This function will panic if called multiple times per session.
    /// This is to prevent replacing the key mid-session.
    #[pg_extern]
    pub fn init(kid: i64, s: JsonB) {
        let key: JwkEcKey = serde_json::from_value(s.0).unwrap();
        let key = PublicKey::from_jwk(&key).unwrap();
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
            let nbf = nbf.as_i64().expect(
                "'nbf' (Not Before) must be an integer representing seconds since unix epoch",
            );
            let nbf = AnyNumeric::from(nbf);
            assert!(nbf < now, "Token used before it is ready")
        }
        if let Some(exp) = payload.get("exp") {
            let exp = exp.as_i64().expect(
                "'exp' (Expiration) must be an integer representing seconds since unix epoch",
            );
            let exp = AnyNumeric::from(exp);
            assert!(now < exp, "Token used after it has expired")
        }
    }

    /// Decrypt the JWT and store it.
    ///
    /// # Panics
    ///
    /// This function will panic if the JWT could not be verified.
    #[pg_extern]
    pub fn jwt_session_init(s: &str) {
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

    /// Extract a value from the shared state.
    #[pg_extern]
    pub fn get(s: &str) -> JsonB {
        JWT.with_borrow(|j| {
            JsonB(
                j.as_ref()
                    .and_then(|j| j.get(s).cloned())
                    .unwrap_or(serde_json::Value::Null),
            )
        })
    }

    #[pg_extern]
    pub fn user_id() -> String {
        match get("sub").0 {
            serde_json::Value::String(s) => s,
            _ => panic!("invalid subject claim in the JWT"),
        }
    }

    fn json_base64_decode<D: DeserializeOwned>(s: &str) -> D {
        let r = Decoder::<Base64UrlUnpadded>::new(s.as_bytes()).unwrap();
        serde_json::from_reader(r).unwrap()
    }
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use std::fmt::Display;
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64ct::{Base64UrlUnpadded, Encoding};
    use p256::ecdsa::signature::Signer;
    use p256::{
        ecdsa::{Signature, SigningKey},
        elliptic_curve::JwkEcKey,
    };
    use p256::{NistP256, PublicKey};
    use pgrx::{prelude::*, JsonB};
    use rand::rngs::OsRng;
    use serde_json::json;

    use crate::auth;

    fn sign_jwt(sk: &SigningKey, header: &str, payload: impl Display) -> String {
        let header = Base64UrlUnpadded::encode_string(header.as_bytes());
        let payload = Base64UrlUnpadded::encode_string(payload.to_string().as_bytes());

        let message = format!("{header}.{payload}");
        let sig: Signature = sk.sign(message.as_bytes());
        let base64_sig = Base64UrlUnpadded::encode_string(&sig.to_bytes());
        format!("{message}.{base64_sig}")
    }

    #[pg_test]
    #[should_panic = "JWK state can only be set once per session."]
    fn init_jwk_twice() {
        let sk = SigningKey::random(&mut OsRng);
        let point = sk.verifying_key().to_encoded_point(false);
        let jwk = JwkEcKey::from_encoded_point::<NistP256>(&point).unwrap();
        let jwk = serde_json::to_value(&jwk).unwrap();

        auth::init(1, JsonB(jwk.clone()));
        auth::init(2, JsonB(jwk));
    }

    #[pg_test]
    #[should_panic = "Key ID mismatch"]
    fn wrong_pid() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk();
        let jwk = JsonB(serde_json::to_value(&jwk).unwrap());

        auth::init(1, jwk);
        auth::jwt_session_init(&sign_jwt(&sk, r#"{"kid":2}"#, r#"{"jti":1}"#));
    }

    #[pg_test]
    #[should_panic = "Token ID must be strictly monotonically increasing"]
    fn wrong_txid() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk();
        let jwk = JsonB(serde_json::to_value(&jwk).unwrap());

        auth::init(1, jwk);
        auth::jwt_session_init(&sign_jwt(&sk, r#"{"kid":1}"#, r#"{"jti":2}"#));
        auth::jwt_session_init(&sign_jwt(&sk, r#"{"kid":1}"#, r#"{"jti":1}"#));
    }

    #[pg_test]
    #[should_panic = "Token used before it is ready"]
    fn invalid_nbf() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk();
        let jwk = JsonB(serde_json::to_value(&jwk).unwrap());

        auth::init(1, jwk);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        auth::jwt_session_init(&sign_jwt(
            &sk,
            r#"{"kid":1}"#,
            json!({"jti": 1, "nbf": now + 10}),
        ));
    }

    #[pg_test]
    #[should_panic = "Token used after it has expired"]
    fn invalid_exp() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk();
        let jwk = JsonB(serde_json::to_value(&jwk).unwrap());

        auth::init(1, jwk);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        auth::jwt_session_init(&sign_jwt(
            &sk,
            r#"{"kid":1}"#,
            json!({"jti": 1, "nbf": now - 10, "exp": now - 5}),
        ));
    }

    #[pg_test]
    fn valid_time() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk();
        let jwk = JsonB(serde_json::to_value(&jwk).unwrap());

        auth::init(1, jwk);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let header = r#"{"kid":1}"#;

        auth::jwt_session_init(&sign_jwt(
            &sk,
            header,
            json!({"jti": 1, "nbf": now - 10, "exp": now + 10}),
        ));
        auth::jwt_session_init(&sign_jwt(&sk, header, json!({"jti": 2, "nbf": now - 10})));
        auth::jwt_session_init(&sign_jwt(&sk, header, json!({"jti": 3, "exp": now + 10})));
    }

    #[pg_test]
    fn test_pg_session_jwt() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk();
        let jwk = JsonB(serde_json::to_value(&jwk).unwrap());

        auth::init(1, jwk);
        let header = r#"{"kid":1}"#;

        auth::jwt_session_init(&sign_jwt(&sk, header, r#"{"sub":"foo","jti":1}"#));
        assert_eq!(auth::user_id(), "foo");

        auth::jwt_session_init(&sign_jwt(&sk, header, r#"{"sub":"bar","jti":2}"#));
        assert_eq!(auth::user_id(), "bar");
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
