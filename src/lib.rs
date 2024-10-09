mod gucs;

use pgrx::prelude::*;

pgrx::pg_module_magic!();

/// inspired from https://docs.rs/pgrx-pg-sys/0.11.4/src/pgrx_pg_sys/submodules/elog.rs.html#243-256
macro_rules! error_code {
    ($errcode:expr, $message:expr $(, $detail:expr)? $(,)?) => {{
        ereport!(PgLogLevel::ERROR, $errcode, $message $(, $detail)?);
        // ereport with ERROR level will trigger a panic anyway. this
        // just helps us with type-coercion since ereport returns `()`
        // but we want `!`.
        unreachable!()
    }};
}

#[allow(non_snake_case)]
#[pg_guard]
pub unsafe extern "C" fn _PG_init() {
    gucs::init();
}

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

    use crate::gucs::{
        NEON_AUTH_JWK, NEON_AUTH_JWK_RUNTIME_PARAM, NEON_AUTH_JWT, NEON_AUTH_JWT_RUNTIME_PARAM,
        NEON_AUTH_KID,
    };

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
    pub fn init() {
        let kid: i64 = NEON_AUTH_KID.get().into();
        let jwk = NEON_AUTH_JWK
            .get()
            .unwrap_or_else(|| {
                error_code!(
                    PgSqlErrorCode::ERRCODE_NO_DATA,
                    format!("Missing runtime parameter: {}", NEON_AUTH_JWK_RUNTIME_PARAM)
                )
            })
            .to_str()
            .unwrap_or_else(|e| {
                error_code!(
                    PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                    format!("Couldn't parse {}", NEON_AUTH_JWK_RUNTIME_PARAM),
                    e.to_string(),
                )
            });
        let key: JwkEcKey = serde_json::from_str(jwk).unwrap_or_else(|e| {
            error_code!(
                PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                "session init requires an ES256 JWK",
                e.to_string(),
            )
        });
        let key = PublicKey::from_jwk(&key).unwrap_or_else(|p256::elliptic_curve::Error| {
            error_code!(
                PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                "session init requires an ES256 JWK",
            )
        });
        let key = VerifyingKey::from(key);
        JWK.with(|j| {
            if j.set(Key { kid, key }).is_err() {
                error_code!(
                    PgSqlErrorCode::ERRCODE_UNIQUE_VIOLATION,
                    "JWK state can only be set once per session.",
                )
            }
        })
    }

    fn verify_signature(key: &Key, body: &str, sig: &str) {
        let mut sig_bytes = GenericArray::default();
        Base64UrlUnpadded::decode(sig, &mut sig_bytes).unwrap_or_else(|_| {
            error_code!(
                PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                "invalid JWT signature encoding",
            )
        });
        let sig = Signature::from_bytes(&sig_bytes).unwrap_or_else(|_| {
            error_code!(
                PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                "invalid JWT signature encoding",
            )
        });

        key.key.verify(body.as_bytes(), &sig).unwrap_or_else(|_| {
            error_code!(
                PgSqlErrorCode::ERRCODE_CHECK_VIOLATION,
                "invalid JWT signature",
            )
        });
    }

    fn verify_key_id(key: &Key, header: &Object) {
        let kid = header
            .get("kid")
            .and_then(|x| x.as_i64())
            .unwrap_or_else(|| {
                error_code!(
                    PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                    "JWT header must contain a valid 'kid' (key ID)",
                )
            });

        if key.kid != kid {
            error_code!(PgSqlErrorCode::ERRCODE_CHECK_VIOLATION, "Key ID mismatch");
        }
    }

    fn verify_token_id(payload: &Object) -> i64 {
        let jti = payload
            .get("jti")
            .and_then(|x| x.as_i64())
            .unwrap_or_else(|| {
                error_code!(
                    PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                    "JWT payload must contain a valid 'jti' (JWT ID)",
                )
            });

        JTI.with_borrow(|t| {
            if jti <= *t {
                error_code!(
                    PgSqlErrorCode::ERRCODE_CHECK_VIOLATION,
                    "Token ID must be strictly monotonically increasing."
                );
            }
        });

        jti
    }

    fn verify_time(payload: &Object) {
        let now = now()
            .to_utc()
            .extract_part(DateTimeParts::Epoch)
            .unwrap_or_else(|| {
                error_code!(
                    PgSqlErrorCode::ERRCODE_INTERNAL_ERROR,
                    "could not get current unix epoch",
                )
            });
        if let Some(nbf) = payload.get("nbf") {
            let nbf = nbf.as_i64().unwrap_or_else(|| {
                error_code!(
                    PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                    "'nbf' (Not Before) must be an integer representing seconds since unix epoch",
                )
            });
            let nbf = AnyNumeric::from(nbf);

            if now < nbf {
                error_code!(
                    PgSqlErrorCode::ERRCODE_CHECK_VIOLATION,
                    "Token used before it is ready",
                )
            }
        }
        if let Some(exp) = payload.get("exp") {
            let exp = exp.as_i64().unwrap_or_else(|| {
                error_code!(
                    PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                    "'exp' (Expiration) must be an integer representing seconds since unix epoch",
                )
            });
            let exp = AnyNumeric::from(exp);

            if exp < now {
                error_code!(
                    PgSqlErrorCode::ERRCODE_CHECK_VIOLATION,
                    "Token used after it has expired",
                )
            }
        }
    }

    /// Decrypt the JWT and store it.
    ///
    /// # Panics
    ///
    /// This function will panic if the JWT could not be verified.
    #[pg_extern]
    pub fn jwt_session_init(jwt: &str) {
        Spi::run(format!("SET {} = '{}'", NEON_AUTH_JWT_RUNTIME_PARAM, jwt).as_str())
            .unwrap_or_else(|e| {
                error_code!(
                    PgSqlErrorCode::ERRCODE_S_R_E_PROHIBITED_SQL_STATEMENT_ATTEMPTED,
                    format!("Couldn't set {}", NEON_AUTH_JWT_RUNTIME_PARAM),
                    e.to_string(),
                )
            });
        set_jwt_cache()
    }

    fn set_jwt_cache() {
        let jwt = NEON_AUTH_JWT
            .get()
            .unwrap_or_else(|| {
                error_code!(
                    PgSqlErrorCode::ERRCODE_NO_DATA,
                    format!("Missing runtime parameter: {}", NEON_AUTH_JWT_RUNTIME_PARAM)
                )
            })
            .to_str()
            .unwrap_or_else(|e| {
                error_code!(
                    PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                    format!("Couldn't parse {}", NEON_AUTH_JWT_RUNTIME_PARAM),
                    e.to_string(),
                )
            });
        let key = JWK.with(|b| {
            b.get()
                .unwrap_or_else(|| {
                    error_code!(
                        PgSqlErrorCode::ERRCODE_NOT_NULL_VIOLATION,
                        "JWK state has not been initialised",
                    )
                })
                .clone()
        });
        let (body, sig) = jwt.rsplit_once('.').unwrap_or_else(|| {
            error_code!(
                PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                "invalid JWT encoding",
            )
        });
        let (header, payload) = body.split_once('.').unwrap_or_else(|| {
            error_code!(
                PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                "invalid JWT encoding",
            )
        });
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
    pub fn session(s: &str) -> JsonB {
        JWK.with(|j| {
            if j.get().is_none() {
                // assuming that running as bgworker
                init();
                set_jwt_cache();
            }
        });

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
        match session("sub").0 {
            serde_json::Value::String(s) => s,
            _ => error_code!(
                PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                "invalid subject claim in the JWT"
            ),
        }
    }

    fn json_base64_decode<D: DeserializeOwned>(s: &str) -> D {
        let r = Decoder::<Base64UrlUnpadded>::new(s.as_bytes()).unwrap_or_else(|e| {
            error_code!(
                PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                "could not decode JWT component",
                e.to_string(),
            )
        });
        serde_json::from_reader(r).unwrap_or_else(|e| {
            error_code!(
                PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                "could not parse JWT component",
                e.to_string(),
            )
        })
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
    use pgrx::prelude::*;
    use rand::rngs::OsRng;
    use serde_json::json;

    use crate::auth;
    use crate::gucs::{
        NEON_AUTH_JWK_RUNTIME_PARAM, NEON_AUTH_JWT, NEON_AUTH_JWT_RUNTIME_PARAM,
        NEON_AUTH_KID_RUNTIME_PARAM,
    };

    fn set_jwk_in_guc(kid: i32, key: String) {
        Spi::run(format!("SET {} = {}", NEON_AUTH_KID_RUNTIME_PARAM, kid).as_str()).unwrap();
        Spi::run(format!("SET {} = '{}'", NEON_AUTH_JWK_RUNTIME_PARAM, key).as_str()).unwrap();
    }

    fn set_jwt_in_guc(jwt: String) {
        Spi::run(format!("SET {} = '{}'", NEON_AUTH_JWT_RUNTIME_PARAM, jwt).as_str()).unwrap();
    }

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

        set_jwk_in_guc(1, serde_json::to_string(&jwk).unwrap());
        auth::init();

        set_jwk_in_guc(2, serde_json::to_string(&jwk).unwrap());
        auth::init();
    }

    #[pg_test]
    #[should_panic = "Key ID mismatch"]
    fn wrong_pid() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk();
        let jwk = serde_json::to_string(&jwk).unwrap();
        set_jwk_in_guc(1, jwk);

        auth::init();
        auth::jwt_session_init(&sign_jwt(&sk, r#"{"kid":2}"#, r#"{"jti":1}"#));
    }

    #[pg_test]
    #[should_panic = "Token ID must be strictly monotonically increasing"]
    fn wrong_txid() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk();
        let jwk = serde_json::to_string(&jwk).unwrap();
        set_jwk_in_guc(1, jwk);

        auth::init();
        auth::jwt_session_init(&sign_jwt(&sk, r#"{"kid":1}"#, r#"{"jti":2}"#));
        auth::jwt_session_init(&sign_jwt(&sk, r#"{"kid":1}"#, r#"{"jti":1}"#));
    }

    #[pg_test]
    #[should_panic = "Token used before it is ready"]
    fn invalid_nbf() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk();
        let jwk = serde_json::to_string(&jwk).unwrap();
        set_jwk_in_guc(1, jwk);

        auth::init();

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
        let jwk = serde_json::to_string(&jwk).unwrap();
        set_jwk_in_guc(1, jwk);

        auth::init();

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
        let jwk = serde_json::to_string(&jwk).unwrap();
        set_jwk_in_guc(1, jwk);

        auth::init();

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
        let jwk = serde_json::to_string(&jwk).unwrap();
        set_jwk_in_guc(1, jwk);

        auth::init();
        let header = r#"{"kid":1}"#;

        let jwt = sign_jwt(&sk, header, r#"{"sub":"foo","jti":1}"#);
        auth::jwt_session_init(&jwt);
        assert_eq!(NEON_AUTH_JWT.get().unwrap().to_str().unwrap(), &jwt);
        assert_eq!(auth::user_id(), "foo");

        let jwt = sign_jwt(&sk, header, r#"{"sub":"bar","jti":2}"#);
        auth::jwt_session_init(&jwt);
        assert_eq!(NEON_AUTH_JWT.get().unwrap().to_str().unwrap(), &jwt);
        assert_eq!(auth::user_id(), "bar");
    }

    // bgworker process exits after execution, because of that we don't need to test case for more
    // than one JWT
    #[pg_test]
    fn test_bgworker() {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = PublicKey::from(sk.verifying_key()).to_jwk();
        let jwk = serde_json::to_string(&jwk).unwrap();
        let header = r#"{"kid":1}"#;
        let jwt = sign_jwt(&sk, header, r#"{"sub":"foo","jti":1}"#);
        set_jwk_in_guc(1, jwk);
        set_jwt_in_guc(jwt);

        assert_eq!(auth::user_id(), "foo");
        assert_eq!(auth::user_id(), "foo");
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
