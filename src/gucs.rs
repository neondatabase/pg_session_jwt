use pgrx::*;
use std::ffi::CStr;

pub static NEON_AUTH_JWK: GucSetting<Option<&'static CStr>> = GucSetting::<Option<&'static CStr>>::new(None);
pub static NEON_AUTH_JWT: GucSetting<Option<&'static CStr>> = GucSetting::<Option<&'static CStr>>::new(None);

pub fn init() {
    GucRegistry::define_string_guc(
        "neon.auth.jwk",
        "JSON Web Key (JWK) userd for JWT validation",
        "Generated per connection by Neon local proxy",
        &NEON_AUTH_JWK,
        GucContext::SuBackend, GucFlags::NOT_WHILE_SEC_REST);

    GucRegistry::define_string_guc(
        "neon.auth.jwt",
        "JSON Web Token (JWT) used for query authorization",
        "Represents user session related claims like user id",
        &NEON_AUTH_JWT,
        GucContext::Suset, GucFlags::NOT_WHILE_SEC_REST);
}
