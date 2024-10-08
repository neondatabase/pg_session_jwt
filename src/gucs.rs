use pgrx::*;
use std::ffi::CStr;

pub static AUTH_FOO: GucSetting<Option<&'static CStr>> = GucSetting::<Option<&'static CStr>>::new(None);

pub fn init() {
    GucRegistry::define_string_guc(
        "auth.foo",
        "foo",
        "bar",
        &AUTH_FOO,
        GucContext::Suset, GucFlags::NOT_WHILE_SEC_REST);
}
