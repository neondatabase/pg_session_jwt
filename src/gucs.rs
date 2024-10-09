use pgrx::*;
use std::ffi::CStr;

pub static NEON_AUTH_KID_RUNTIME_PARAM: &str = "neon.auth.kid";
pub static NEON_AUTH_KID: GucSetting<i32> = GucSetting::<i32>::new(0);
pub static NEON_AUTH_JWK_RUNTIME_PARAM: &str = "neon.auth.jwk";
pub static NEON_AUTH_JWK: GucSetting<Option<&'static CStr>> =
    GucSetting::<Option<&'static CStr>>::new(None);
pub static NEON_AUTH_JWT_RUNTIME_PARAM: &str = "neon.auth.jwt";
pub static NEON_AUTH_JWT: GucSetting<Option<&'static CStr>> =
    GucSetting::<Option<&'static CStr>>::new(None);

pub fn init() {
    GucRegistry::define_int_guc(
        NEON_AUTH_KID_RUNTIME_PARAM,
        "ID of JSON Web Key (JWK)",
        "Generated per connection by Neon local proxy",
        &NEON_AUTH_KID,
        0,
        i32::MAX,
        GucContext::Suset, // we should use GucContext::SuBackend but this breaks unit tests
        GucFlags::NOT_WHILE_SEC_REST,
    );

    GucRegistry::define_string_guc(
        NEON_AUTH_JWK_RUNTIME_PARAM,
        "JSON Web Key (JWK) userd for JWT validation",
        "Generated per connection by Neon local proxy",
        &NEON_AUTH_JWK,
        GucContext::Suset, // we should use GucContext::SuBackend but this breaks unit tests
        GucFlags::NOT_WHILE_SEC_REST,
    );

    GucRegistry::define_string_guc(
        NEON_AUTH_JWT_RUNTIME_PARAM,
        "JSON Web Token (JWT) used for query authorization",
        "Represents authenticated user session related claims like user ID",
        &NEON_AUTH_JWT,
        GucContext::Suset,
        GucFlags::NOT_WHILE_SEC_REST,
    );
}
