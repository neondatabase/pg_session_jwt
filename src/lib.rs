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
    };

    type Object = serde_json::Map<String, serde_json::Value>;

    thread_local! {
        static JWK: OnceCell<VerifyingKey> = const { OnceCell::new() };
        static JWT: RefCell<Option<(String, Object)>> = const { RefCell::new(None) };
        static JTI: RefCell<i64> = const { RefCell::new(0) };
    }

    fn get_jwk_guc() -> VerifyingKey {
        let jwk = NEON_AUTH_JWK
            .get()
            .unwrap_or_else(|| {
                error_code!(
                    PgSqlErrorCode::ERRCODE_NO_DATA,
                    format!("Missing runtime parameter: {}", NEON_AUTH_JWK_RUNTIME_PARAM)
                )
            })
            .to_bytes();

        JWK.with(|b| {
            *b.get_or_init(|| {
                let jwk: JwkEcKey = serde_json::from_slice(jwk).unwrap_or_else(|e| {
                    error_code!(
                        PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                        "pg_session_jwt.jwk requires an ES256 JWK",
                        e.to_string(),
                    )
                });
                let key =
                    PublicKey::from_jwk(&jwk).unwrap_or_else(|p256::elliptic_curve::Error| {
                        error_code!(
                            PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                            "pg_session_jwt.jwk requires an ES256 JWK",
                        )
                    });
                VerifyingKey::from(key)
            })
        })
    }

    /// Set the public key for this postgres session.
    #[pg_extern]
    pub fn init() {
        get_jwk_guc();
    }

    fn verify_signature(key: &VerifyingKey, body: &str, sig: &str) {
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

        key.verify(body.as_bytes(), &sig).unwrap_or_else(|_| {
            error_code!(
                PgSqlErrorCode::ERRCODE_CHECK_VIOLATION,
                "invalid JWT signature",
            )
        });
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
        validate_jwt();
    }

    fn get_jwt_guc() -> Option<&'static str> {
        Some(NEON_AUTH_JWT.get()?.to_str().unwrap_or_else(|e| {
            error_code!(
                PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                format!("invalid JWT parameter {}", NEON_AUTH_JWT_RUNTIME_PARAM),
                e.to_string(),
            )
        }))
    }

    fn validate_jwt() -> Option<serde_json::Map<String, serde_json::Value>> {
        let jwt = get_jwt_guc()?;
        let key = get_jwk_guc();

        JWT.with_borrow_mut(|cached_jwt| {
            match cached_jwt {
                Some((cached_jwt, payload)) if cached_jwt == jwt => {
                    log_audit_validated_jwt(payload);
                    Some(payload.clone())
                },
                _ => {
                    let (body, sig) = jwt.rsplit_once('.').unwrap_or_else(|| {
                        error_code!(
                            PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                            "invalid JWT encoding",
                        )
                    });
                    let (_, payload) = body.split_once('.').unwrap_or_else(|| {
                        error_code!(
                            PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                            "invalid JWT encoding",
                        )
                    });

                    verify_signature(&key, body, sig);

                    let payload: Object = json_base64_decode(payload);
                    let jti = verify_token_id(&payload);
                    verify_time(&payload);

                    // update state
                    JTI.replace(jti);
                    *cached_jwt = Some((jwt.to_string(), payload.clone()));
                    log_audit_validated_jwt(&payload);
                    Some(payload)
                }
            }
        })
    }

    fn log_audit_validated_jwt(payload: &Object) {
        log!(
            "Validated JWT: sub={} aud={}",
            payload.get("sub").unwrap_or(&"".into()),
            payload.get("aud").unwrap_or(&"".into())
        );
    }

    /// Extract a value from the shared state.
    #[pg_extern(parallel_safe, stable)]
    pub fn session() -> JsonB {
        JsonB(validate_jwt().map_or(serde_json::Value::Null, serde_json::Value::Object))
    }

    #[pg_extern(parallel_safe, stable)]
    pub fn user_id() -> Option<String> {
        match validate_jwt()?.get("sub")? {
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
