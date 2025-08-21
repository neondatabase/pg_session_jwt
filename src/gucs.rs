use pgrx::*;
use std::ffi::{CStr, CString};

pub static NEON_AUTH_JWK_RUNTIME_PARAM: &CStr = c"pg_session_jwt.jwk";
pub static NEON_AUTH_JWK: GucSetting<Option<CString>> =
    GucSetting::<Option<CString>>::new(None);
pub static NEON_AUTH_JWT_RUNTIME_PARAM: &CStr = c"pg_session_jwt.jwt";
pub static NEON_AUTH_JWT: GucSetting<Option<CString>> =
    GucSetting::<Option<CString>>::new(None);
pub static NEON_AUTH_ENABLE_AUDIT_LOG_PARAM: &CStr = c"pg_session_jwt.audit_log";
pub static NEON_AUTH_ENABLE_AUDIT_LOG: GucSetting<Option<CString>> =
    GucSetting::<Option<CString>>::new(None);
pub static POSTGREST_JWT_RUNTIME_PARAM: &CStr = c"request.jwt.claims";
pub static POSTGREST_JWT: GucSetting<Option<CString>> =
    GucSetting::<Option<CString>>::new(None);

pub fn init() {
    GucRegistry::define_string_guc(
        NEON_AUTH_JWK_RUNTIME_PARAM,
        c"JSON Web Key (JWK) used for JWT validation",
        c"Generated per connection by Neon local proxy",
        &NEON_AUTH_JWK,
        GucContext::Backend,
        GucFlags::NOT_WHILE_SEC_REST | GucFlags::NO_RESET_ALL,
    );

    GucRegistry::define_string_guc(
        NEON_AUTH_JWT_RUNTIME_PARAM,
        c"JSON Web Token (JWT) used for query authorization",
        c"Represents authenticated user session related claims like user ID",
        &NEON_AUTH_JWT,
        GucContext::Userset,
        GucFlags::NOT_WHILE_SEC_REST,
    );

    GucRegistry::define_string_guc(
        NEON_AUTH_ENABLE_AUDIT_LOG_PARAM,
        c"Enable audit logs",
        c"Setting as 'on' enables audit logs that are produced each time JWT is validated and/or read",
        &NEON_AUTH_ENABLE_AUDIT_LOG,
        GucContext::Suset,
        GucFlags::NOT_WHILE_SEC_REST,
    );

    GucRegistry::define_string_guc(
        POSTGREST_JWT_RUNTIME_PARAM,
        c"JSON Web Token (JWT) used for query authorization",
        c"PostgREST compatible GUC. Represents authenticated user session related claims like user ID",
        &POSTGREST_JWT,
        GucContext::Userset,
        GucFlags::NOT_WHILE_SEC_REST,
    );
}
