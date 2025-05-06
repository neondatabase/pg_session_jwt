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

mod gucs;

#[allow(non_snake_case)]
#[pg_guard]
pub unsafe extern "C-unwind" fn _PG_init() {
    gucs::init();
}

#[pg_schema]
pub mod auth {
    use std::cell::RefCell;
    use std::time::Duration;

    use pgrx::prelude::*;
    use pgrx::JsonB;

    use ed25519_dalek::{Signature, VerifyingKey};

    use base64ct::{Base64UrlUnpadded, Decoder, Encoding};
    use serde::de::DeserializeOwned;

    use crate::gucs::NEON_AUTH_JWT_RUNTIME_PARAM;
    use crate::gucs::{
        can_log_audit, get_jwk_guc, get_jwt_guc, get_postgrest_claims_from_guc, jwk_set,
        match_jwt_guc, POSTGREST_JWT_RUNTIME_PARAM,
    };

    type Object = serde_json::Map<String, serde_json::Value>;

    /// local-proxy/auth-broker use a leeway of 30s. We add a little
    /// bit more leeway here to account for any delays before getting to the extension.
    pub const CLOCK_SKEW_LEEWAY: Duration = Duration::from_secs(60);

    thread_local! {
        static JWT: RefCell<Option<(String, Object)>> = const { RefCell::new(None) };
        static JTI: RefCell<i64> = const { RefCell::new(0) };
    }

    /// Set the public key for this postgres session.
    #[pg_extern]
    pub fn init() {
        get_jwk_guc();
    }

    fn verify_signature(key: &VerifyingKey, body: &str, sig: &str) {
        let mut sig_bytes = [0; 64];
        Base64UrlUnpadded::decode(sig, &mut sig_bytes).unwrap_or_else(|_| {
            error_code!(
                PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                "invalid JWT signature encoding",
            )
        });
        let sig = Signature::from_bytes(&sig_bytes);

        key.verify_strict(body.as_bytes(), &sig)
            .unwrap_or_else(|_| {
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
            let nbf_num = AnyNumeric::from(nbf);

            let leeway = AnyNumeric::from(CLOCK_SKEW_LEEWAY.as_secs());
            if now.clone() + leeway < nbf_num {
                error_code!(
                    PgSqlErrorCode::ERRCODE_CHECK_VIOLATION,
                    "Token used before it is ready",
                    format!("nbf={nbf}")
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
            let exp_num = AnyNumeric::from(exp);

            let leeway = AnyNumeric::from(CLOCK_SKEW_LEEWAY.as_secs());
            if exp_num + leeway < now {
                error_code!(
                    PgSqlErrorCode::ERRCODE_CHECK_VIOLATION,
                    "Token used after it has expired",
                    format!("exp={exp}")
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

    fn validate_jwt() -> Option<serde_json::Map<String, serde_json::Value>> {
        JWT.with_borrow_mut(|cached_jwt| {
            match cached_jwt {
                Some((cached_jwt, payload)) if match_jwt_guc(&cached_jwt) => {
                    log_audit_validated_jwt(payload);
                    Some(payload.clone())
                }
                _ => {
                    let jwt = get_jwt_guc()?;
                    let key = get_jwk_guc();

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
                    *cached_jwt = Some((jwt, payload.clone()));
                    log_audit_validated_jwt(&payload);
                    Some(payload)
                }
            }
        })
    }

    fn log_audit_validated_jwt(payload: &Object) {
        if !can_log_audit() {
            return;
        }

        log!(
            "JWT issued for sub={} and aud={} was succesfully validated",
            payload.get("sub").unwrap_or(&"".into()),
            payload.get("aud").unwrap_or(&"".into())
        );
    }

    fn log_audit_guc_claims(guc: &str, claims: Option<&Object>) {
        if !can_log_audit() {
            return;
        }

        match claims {
            Some(payload) => log!(
                "JWT claims from GUC '{}': sub={} and aud={}",
                guc,
                payload.get("sub").unwrap_or(&"".into()),
                payload.get("aud").unwrap_or(&"".into())
            ),
            None => log!("No JWT claims found in GUC variable: {}", guc),
        }
    }

    fn get_postgrest_claims() -> Option<serde_json::Value> {
        let claims = get_postgrest_claims_from_guc();

        log_audit_guc_claims(
            POSTGREST_JWT_RUNTIME_PARAM,
            claims.as_ref().and_then(|v| v.as_object()),
        );
        claims
    }

    /// Extract a value from the shared state.
    #[pg_extern(parallel_safe, stable)]
    pub fn session() -> JsonB {
        // If the JWK is not defined, we fallback to the request.jwt.claims GUC
        // https://docs.postgrest.org/en/v12/references/transactions.html#request-headers-cookies-and-jwt-claims
        if !jwk_set() {
            return JsonB(get_postgrest_claims().unwrap_or(serde_json::Value::Null));
        }
        JsonB(validate_jwt().map_or(serde_json::Value::Null, serde_json::Value::Object))
    }

    #[pg_extern(parallel_safe, stable)]
    pub fn user_id() -> Option<String> {
        // https://docs.postgrest.org/en/v12/references/transactions.html#request-headers-cookies-and-jwt-claims
        if !jwk_set() {
            // Get subject from the claims JSONB
            return get_postgrest_claims()
                .and_then(|json| json.get("sub").cloned())
                .and_then(|s| s.as_str().map(|s| s.to_owned()));
        }

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
