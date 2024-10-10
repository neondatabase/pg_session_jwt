mod gucs;

use p256::elliptic_curve::JwkEcKey;
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

/// An Elliptic Curve JSON Web Key.
///
/// This type is defined in [RFC7517 Section 4].
///
/// [RFC7517 Section 4]: https://datatracker.ietf.org/doc/html/rfc7517#section-4
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
struct JwkEc {
    /// The key material.
    #[serde(flatten)]
    key: JwkEcKey,

    // The key parameters.
    kid: i64,
}

#[pg_schema]
pub mod auth {
    use std::cell::{OnceCell, RefCell};

    use base64ct::{Base64UrlUnpadded, Decoder, Encoding};
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::elliptic_curve::generic_array::GenericArray;
    use p256::PublicKey;
    use pgrx::prelude::*;
    use pgrx::JsonB;
    use serde::de::DeserializeOwned;

    use crate::gucs::{
        NEON_AUTH_JWK, NEON_AUTH_JWK_RUNTIME_PARAM, NEON_AUTH_JWT, NEON_AUTH_JWT_RUNTIME_PARAM,
    };
    use crate::JwkEc;

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

        let jwk: JwkEc = serde_json::from_str(jwk).unwrap_or_else(|e| {
            error_code!(
                PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                "session init requires an ES256 JWK",
                e.to_string(),
            )
        });
        let key = PublicKey::from_jwk(&jwk.key).unwrap_or_else(|p256::elliptic_curve::Error| {
            error_code!(
                PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                "session init requires an ES256 JWK",
            )
        });
        let key = VerifyingKey::from(key);
        JWK.with(|j| {
            if j.set(Key { kid: jwk.kid, key }).is_err() {
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
        Spi::run(
            format!(
                "SET {} = {}",
                NEON_AUTH_JWT_RUNTIME_PARAM,
                spi::quote_literal(jwt)
            )
            .as_str(),
        )
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
    pub fn session() -> JsonB {
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
                    .cloned()
                    .map_or(serde_json::Value::Null, serde_json::Value::Object),
            )
        })
    }

    #[pg_extern]
    pub fn user_id() -> Option<String> {
        match session().0.get("sub")? {
            serde_json::Value::String(s) => Some(s.clone()),
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
