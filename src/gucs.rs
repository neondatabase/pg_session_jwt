// IMPORTANT: `pgrx::guc` has some unsoundness in the API.
// See <https://github.com/pgcentralfoundation/pgrx/issues/2055>.

use ed25519_dalek::VerifyingKey;
use pgrx::*;
use std::{cell::OnceCell, ffi::CStr};

static NEON_AUTH_JWK_RUNTIME_PARAM: &str = "pg_session_jwt.jwk";
static NEON_AUTH_JWK: GucSetting<Option<&'static CStr>> =
    GucSetting::<Option<&'static CStr>>::new(None);

pub static NEON_AUTH_JWT_RUNTIME_PARAM: &str = "pg_session_jwt.jwt";
static NEON_AUTH_JWT: GucSetting<Option<&'static CStr>> =
    GucSetting::<Option<&'static CStr>>::new(None);

static NEON_AUTH_ENABLE_AUDIT_LOG_PARAM: &str = "pg_session_jwt.audit_log";
static NEON_AUTH_ENABLE_AUDIT_LOG: GucSetting<Option<&'static CStr>> =
    GucSetting::<Option<&'static CStr>>::new(None);

pub static POSTGREST_JWT_RUNTIME_PARAM: &str = "request.jwt.claims";
static POSTGREST_JWT: GucSetting<Option<&'static CStr>> =
    GucSetting::<Option<&'static CStr>>::new(None);

pub fn init() {
    // Safety: our GucSetting values are all `&'static`.

    GucRegistry::define_string_guc(
        NEON_AUTH_JWK_RUNTIME_PARAM,
        "JSON Web Key (JWK) used for JWT validation",
        "Generated per connection by Neon local proxy",
        &NEON_AUTH_JWK,
        GucContext::Backend,
        GucFlags::NOT_WHILE_SEC_REST | GucFlags::NO_RESET_ALL,
    );

    GucRegistry::define_string_guc(
        NEON_AUTH_JWT_RUNTIME_PARAM,
        "JSON Web Token (JWT) used for query authorization",
        "Represents authenticated user session related claims like user ID",
        &NEON_AUTH_JWT,
        GucContext::Userset,
        GucFlags::NOT_WHILE_SEC_REST,
    );

    GucRegistry::define_string_guc(
        NEON_AUTH_ENABLE_AUDIT_LOG_PARAM,
        "Enable audit logs",
        "Setting as 'on' enables audit logs that are produced each time JWT is validated and/or read",
        &NEON_AUTH_ENABLE_AUDIT_LOG,
        GucContext::Suset,
        GucFlags::NOT_WHILE_SEC_REST,
    );

    GucRegistry::define_string_guc(
        POSTGREST_JWT_RUNTIME_PARAM,
        "JSON Web Token (JWT) used for query authorization",
        "PostgREST compatible GUC. Represents authenticated user session related claims like user ID",
        &POSTGREST_JWT,
        GucContext::Userset,
        GucFlags::NOT_WHILE_SEC_REST,
    );
}

pub fn can_log_audit() -> bool {
    // Safety: the NEON_AUTH_ENABLE_AUDIT_LOG GUC cannot change while during this function.
    let log_var = NEON_AUTH_ENABLE_AUDIT_LOG.get().map(|x| x.to_bytes());
    matches!(log_var, Some(b"on"))
}

pub fn get_jwk_guc() -> VerifyingKey {
    thread_local! {
        static JWK: OnceCell<VerifyingKey> = const { OnceCell::new() };
    }

    /// A octet key pair CFRG-curve key, as defined in [RFC 8037]
    ///
    /// [RFC 8037]: https://www.rfc-editor.org/rfc/rfc8037
    #[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
    pub struct Ed25519Okp {
        pub kty: Kty,

        /// The CFRG curve.
        pub crv: OkpCurves,

        /// The public key.
        pub x: jose_jwk::jose_b64::serde::Bytes<[u8; 32]>,
    }

    /// The CFRG Curve.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Deserialize)]
    #[non_exhaustive]
    pub enum Kty {
        OKP,
    }

    /// The CFRG Curve.
    #[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Deserialize)]
    #[non_exhaustive]
    pub enum OkpCurves {
        Ed25519,
    }

    JWK.with(|b| {
        *b.get_or_init(|| {
            // Safety: the NEON_AUTH_JWK GUC cannot change while during this function.
            let jwk = NEON_AUTH_JWK
                .get()
                .unwrap_or_else(|| {
                    error_code!(
                        PgSqlErrorCode::ERRCODE_NO_DATA,
                        format!("Missing runtime parameter: {}", NEON_AUTH_JWK_RUNTIME_PARAM)
                    )
                })
                .to_bytes();

            let jwk: Ed25519Okp = serde_json::from_slice(jwk).unwrap_or_else(|e| {
                error_code!(
                    PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                    "pg_session_jwt.jwk requires an ES256 JWK",
                    e.to_string(),
                )
            });

            VerifyingKey::from_bytes(&jwk.x).unwrap_or_else(|e| {
                error_code!(
                    PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
                    "pg_session_jwt.jwk requires an ES256 JWK",
                    e.to_string()
                )
            })
        })
    })
}

pub fn jwk_set() -> bool {
    // Safety: the NEON_AUTH_JWK GUC cannot change while during this function.
    NEON_AUTH_JWK.get().is_some()
}

pub fn get_jwt_guc() -> Option<String> {
    // Safety: the NEON_AUTH_JWT GUC cannot change while during this function.
    let jwt = NEON_AUTH_JWT.get()?;

    let jwt_str = jwt.to_str().unwrap_or_else(|e| {
        error_code!(
            PgSqlErrorCode::ERRCODE_DATATYPE_MISMATCH,
            format!("invalid JWT parameter {}", NEON_AUTH_JWT_RUNTIME_PARAM),
            e.to_string(),
        )
    });

    Some(jwt_str.to_owned())
}

pub fn match_jwt_guc(s: &str) -> bool {
    // Safety: the NEON_AUTH_JWT GUC cannot change while during this function.
    match NEON_AUTH_JWT.get() {
        Some(x) => x.to_bytes() == s.as_bytes(),
        None => false,
    }
}

pub fn get_postgrest_claims_from_guc() -> Option<serde_json::Value> {
    // Safety: the POSTGREST_JWT GUC cannot change while during this function.
    serde_json::from_str(POSTGREST_JWT.get()?.to_str().unwrap_or("")).ok()
}
