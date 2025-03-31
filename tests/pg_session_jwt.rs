use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey};
use jose_jwk::{jose_b64, Okp};
use libtest_mimic::{run, Trial};
use rand::rngs::OsRng;
use serde_json::json;

fn main() -> ExitCode {
    let mut args = libtest_mimic::Arguments::from_args();
    // fixes concurrent update failures
    args.test_threads = Some(1);

    let mut tests = vec![];

    let err = "Token ID must be strictly monotonically increasing.";
    tests.push(test_fn("wrong_txid", Some(err), wrong_txid));

    let err = "Token used before it is ready";
    tests.push(test_fn("invalid_nbf", Some(err), invalid_nbf));

    let err = "Token used after it has expired";
    tests.push(test_fn("invalid_exp", Some(err), invalid_exp));

    tests.push(test_fn("valid_time", None, valid_time));
    tests.push(test_fn("test_pg_session_jwt", None, test_pg_session_jwt));
    tests.push(test_fn("test_bgworker", None, test_bgworker));
    tests.push(test_fn(
        "test_jwt_claim_sub_with_jwk",
        None,
        test_jwt_claim_sub_with_jwk,
    ));
    tests.push(test_without_jwk(
        "test_jwt_claim_sub_fallback_when_set",
        test_jwt_claim_sub_fallback_when_set,
    ));
    tests.push(test_without_jwk(
        "test_jwt_claim_sub_fallback_when_not_set",
        test_jwt_claim_sub_fallback_when_not_set,
    ));
    tests.push(test_fn(
        "test_session_with_jwk",
        None,
        test_session_with_jwk,
    ));
    tests.push(test_without_jwk(
        "test_session_fallback_when_set",
        test_session_fallback_when_set,
    ));
    tests.push(test_without_jwk(
        "test_session_fallback_when_not_set",
        test_session_fallback_when_not_set,
    ));

    run(&args, tests).exit_code()
}

// bgworker process exits after execution, because of that we don't need to test case for more
// than one JWT
fn test_fn<F>(name: &str, error: Option<&'static str>, f: F) -> Trial
where
    F: for<'a, 'b> FnOnce(&'a SigningKey, &'b mut postgres::Client) -> Result<(), postgres::Error>
        + Send
        + 'static,
{
    let sk = SigningKey::generate(&mut OsRng);
    let jwk = create_jwk(&sk);
    let options = format!("-c {NEON_AUTH_JWK_RUNTIME_PARAM}={jwk}");

    Trial::test(name, move || {
        pgrx_tests::run_test(Some(&options), error, vec![], move |tx| f(&sk, tx))
            .map_err(libtest_mimic::Failed::from)
    })
}

// Helper function for tests that don't need JWK
fn test_without_jwk<F>(name: &str, f: F) -> Trial
where
    F: FnOnce(&mut postgres::Client) -> Result<(), postgres::Error> + Send + 'static,
{
    Trial::test(name, move || {
        pgrx_tests::run_test(None, None, vec![], f).map_err(libtest_mimic::Failed::from)
    })
}

fn wrong_txid(sk: &SigningKey, tx: &mut postgres::Client) -> Result<(), postgres::Error> {
    let jwt1 = sign_jwt(sk, r#"{"kid":1}"#, r#"{"jti":1}"#);
    let jwt2 = sign_jwt(sk, r#"{"kid":1}"#, r#"{"jti":2}"#);

    tx.execute("select auth.init()", &[])?;
    tx.execute("select auth.jwt_session_init($1)", &[&jwt2])?;
    tx.execute("select auth.jwt_session_init($1)", &[&jwt1])?;

    Ok(())
}

fn invalid_nbf(sk: &SigningKey, tx: &mut postgres::Client) -> Result<(), postgres::Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let jwt = sign_jwt(sk, r#"{"kid":1}"#, json!({"jti": 1, "nbf": now + 10}));

    tx.execute("select auth.init()", &[])?;
    tx.execute("select auth.jwt_session_init($1)", &[&jwt])?;

    Ok(())
}

fn invalid_exp(sk: &SigningKey, tx: &mut postgres::Client) -> Result<(), postgres::Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let jwt = sign_jwt(
        sk,
        r#"{"kid":1}"#,
        json!({"jti": 1,  "nbf": now - 10, "exp": now - 5}),
    );

    tx.execute("select auth.init()", &[])?;
    tx.execute("select auth.jwt_session_init($1)", &[&jwt])?;

    Ok(())
}

fn valid_time(sk: &SigningKey, tx: &mut postgres::Client) -> Result<(), postgres::Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let header = r#"{"kid":1}"#;
    let jwt1 = sign_jwt(
        sk,
        header,
        json!({"jti": 1, "nbf": now - 10, "exp": now + 10}),
    );
    let jwt2 = sign_jwt(sk, header, json!({"jti": 2, "nbf": now - 10}));
    let jwt3 = sign_jwt(sk, header, json!({"jti": 3, "exp": now + 10}));

    tx.execute("select auth.init()", &[])?;
    tx.execute("select auth.jwt_session_init($1)", &[&jwt1])?;
    tx.execute("select auth.jwt_session_init($1)", &[&jwt2])?;
    tx.execute("select auth.jwt_session_init($1)", &[&jwt3])?;

    Ok(())
}

fn test_pg_session_jwt(sk: &SigningKey, tx: &mut postgres::Client) -> Result<(), postgres::Error> {
    let header = r#"{"kid":1}"#;
    let jwt1 = sign_jwt(sk, header, r#"{"sub":"foo","jti":1}"#);
    let jwt2 = sign_jwt(sk, header, r#"{"sub":"bar","jti":2}"#);

    tx.execute("select auth.init()", &[])?;
    tx.execute("select auth.jwt_session_init($1)", &[&jwt1])?;
    let user_id = tx.query_one("select auth.user_id()", &[])?;
    let user_id = user_id.get::<_, String>("user_id");
    assert_eq!(user_id, "foo");

    tx.execute("select auth.jwt_session_init($1)", &[&jwt2])?;
    let user_id = tx.query_one("select auth.user_id()", &[])?;
    let user_id = user_id.get::<_, String>("user_id");
    assert_eq!(user_id, "bar");

    Ok(())
}

// bgworker process exits after execution, because of that we don't need to test case for more
// than one JWT
fn test_bgworker(sk: &SigningKey, tx: &mut postgres::Client) -> Result<(), postgres::Error> {
    let header = r#"{"kid":1}"#;
    let jwt = sign_jwt(sk, header, r#"{"sub":"foo","jti":1}"#);

    tx.execute(&format!("set pg_session_jwt.jwt = '{jwt}'"), &[])?;
    let user_id = tx.query_one("select auth.user_id()", &[])?;
    let user_id = user_id.get::<_, String>("user_id");
    assert_eq!(user_id, "foo");

    Ok(())
}

fn test_jwt_claim_sub_fallback_when_set(tx: &mut postgres::Client) -> Result<(), postgres::Error> {
    // Test when JWK is not defined and request.jwt.claim.sub is set
    tx.execute("SET request.jwt.claim.sub = 'test-user'", &[])?;
    let user_id = tx.query_one("SELECT auth.user_id()", &[])?;
    let user_id: Option<String> = user_id.get(0);
    assert_eq!(
        user_id,
        Some("test-user".to_string()),
        "Should return the value from request.jwt.claim.sub when set"
    );

    Ok(())
}

fn test_jwt_claim_sub_fallback_when_not_set(
    tx: &mut postgres::Client,
) -> Result<(), postgres::Error> {
    // Test when JWK is not defined and request.jwt.claim.sub is not set
    tx.execute("RESET request.jwt.claim.sub", &[])?;
    let user_id = tx.query_one("SELECT auth.user_id()", &[])?;
    let user_id: Option<String> = user_id.get(0);
    assert_eq!(
        user_id, None,
        "Should return NULL when request.jwt.claim.sub is not set"
    );

    Ok(())
}

fn test_jwt_claim_sub_with_jwk(
    sk: &SigningKey,
    tx: &mut postgres::Client,
) -> Result<(), postgres::Error> {
    let header = r#"{"kid":1}"#;
    let jwt = sign_jwt(sk, header, r#"{"sub":"jwt-user","jti":1}"#);

    // Initialize JWT session
    tx.execute("select auth.init()", &[])?;
    tx.execute("select auth.jwt_session_init($1)", &[&jwt])?;

    // Set request.jwt.claim.sub, but it should be ignored since JWK is defined
    tx.execute("SET request.jwt.claim.sub = 'fallback-user'", &[])?;
    let user_id = tx.query_one("SELECT auth.user_id()", &[])?;
    let user_id: Option<String> = user_id.get(0);
    assert_eq!(
        user_id,
        Some("jwt-user".to_string()),
        "Should use JWT sub claim when JWK is defined"
    );

    Ok(())
}

fn test_session_with_jwk(sk: &SigningKey, tx: &mut postgres::Client) -> Result<(), postgres::Error> {
    let header = r#"{"kid":1}"#;
    let jwt = sign_jwt(sk, header, r#"{"sub":"jwt-user","jti":1,"role":"admin"}"#);

    // Initialize JWT session
    tx.execute("select auth.init()", &[])?;
    tx.execute("select auth.jwt_session_init($1)", &[&jwt])?;

    // Set request.jwt.claims, but it should be ignored since JWK is defined
    tx.execute("SET request.jwt.claims = '{\"sub\":\"fallback-user\",\"role\":\"user\"}'", &[])?;
    
    let sub: Option<String> = tx.query_one("SELECT (auth.session()->>'sub')", &[])?.get(0);
    assert_eq!(sub, Some("jwt-user".to_string()), "Should use JWT sub claim when JWK is defined");
    
    let role: Option<String> = tx.query_one("SELECT (auth.session()->>'role')", &[])?.get(0);
    assert_eq!(role, Some("admin".to_string()), "Should use JWT role claim when JWK is defined");

    Ok(())
}

fn test_session_fallback_when_set(tx: &mut postgres::Client) -> Result<(), postgres::Error> {
    // Test when JWK is not defined and request.jwt.claims is set
    tx.execute("SET request.jwt.claims = '{\"sub\":\"test-user\",\"role\":\"admin\"}'", &[])?;
    
    let sub: Option<String> = tx.query_one("SELECT (auth.session()->>'sub')", &[])?.get(0);
    assert_eq!(
        sub,
        Some("test-user".to_string()),
        "Should return sub from request.jwt.claims when set"
    );
    
    let role: Option<String> = tx.query_one("SELECT (auth.session()->>'role')", &[])?.get(0);
    assert_eq!(
        role,
        Some("admin".to_string()),
        "Should return role from request.jwt.claims when set"
    );

    Ok(())
}

fn test_session_fallback_when_not_set(tx: &mut postgres::Client) -> Result<(), postgres::Error> {
    // Test when JWK is not defined and request.jwt.claims is not set
    tx.execute("RESET request.jwt.claims", &[])?;
    
    let session: String = tx.query_one("SELECT auth.session()::text", &[])?.get(0);
    assert_eq!(session, "null", "Should return null when request.jwt.claims is not set");

    let is_null: bool = tx.query_one("SELECT auth.session() IS NULL", &[])?.get(0);
    assert!(!is_null, "Session should return JSON null, not SQL NULL");

    Ok(())
}

static NEON_AUTH_JWK_RUNTIME_PARAM: &str = "pg_session_jwt.jwk";

fn sign_jwt(sk: &SigningKey, header: &str, payload: impl ToString) -> String {
    let header = Base64UrlUnpadded::encode_string(header.as_bytes());
    let payload = Base64UrlUnpadded::encode_string(payload.to_string().as_bytes());

    let message = format!("{header}.{payload}");
    let sig: Signature = sk.sign(message.as_bytes());
    let base64_sig = Base64UrlUnpadded::encode_string(&sig.to_bytes());
    format!("{message}.{base64_sig}")
}

fn create_jwk(sk: &SigningKey) -> String {
    let key = sk.verifying_key().to_bytes();
    let key = jose_jwk::Key::Okp(Okp {
        crv: jose_jwk::OkpCurves::Ed25519,
        x: jose_b64::serde::Bytes::from(key.to_vec()),
        d: None,
    });
    serde_json::to_string(&key).unwrap()
}
