use std::process::ExitCode;

use base64ct::{Base64UrlUnpadded, Encoding};
use libtest_mimic::{run, Trial};
use p256::ecdsa::signature::Signer;
use p256::{
    ecdsa::{Signature, SigningKey},
    elliptic_curve::JwkEcKey,
    NistP256,
};
use rand::rngs::OsRng;
use serde::Serialize;

pub static NEON_AUTH_JWK_RUNTIME_PARAM: &str = "neon.auth.jwk";
pub static NEON_AUTH_JWT_RUNTIME_PARAM: &str = "neon.auth.jwt";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JwkEc {
    /// The key material.
    #[serde(flatten)]
    pub key: JwkEcKey,

    // The key parameters.
    pub kid: i64,
}

fn main() -> ExitCode {
    let args = libtest_mimic::Arguments::from_args();

    let mut tests = vec![];

    tests.push(Trial::test("wrong_txid", move || {
        let sk = SigningKey::random(&mut OsRng);
        let jwk = create_jwk(&sk, 1);
        let options = format!("-c {NEON_AUTH_JWK_RUNTIME_PARAM}={jwk}");

        let error = "Token ID must be strictly monotonically increasing.";
        pgrx_tests::run_test(Some(&options), Some(error), vec![], |tx| {
            let jwt1 = sign_jwt(&sk, r#"{"kid":1}"#, r#"{"jti":1}"#);
            let jwt2 = sign_jwt(&sk, r#"{"kid":1}"#, r#"{"jti":2}"#);

            tx.execute("select auth.init()", &[])?;
            tx.execute("select auth.jwt_session_init($1)", &[&jwt2])?;
            tx.execute("select auth.jwt_session_init($1)", &[&jwt1])?;

            Ok(())
        })
        .map_err(|e| libtest_mimic::Failed::from(e))
    }));

    run(&args, tests).exit_code()
}

fn sign_jwt(sk: &SigningKey, header: &str, payload: impl ToString) -> String {
    let header = Base64UrlUnpadded::encode_string(header.as_bytes());
    let payload = Base64UrlUnpadded::encode_string(payload.to_string().as_bytes());

    let message = format!("{header}.{payload}");
    let sig: Signature = sk.sign(message.as_bytes());
    let base64_sig = Base64UrlUnpadded::encode_string(&sig.to_bytes());
    format!("{message}.{base64_sig}")
}

fn create_jwk(sk: &SigningKey, kid: i64) -> String {
    let point = sk.verifying_key().to_encoded_point(false);
    let key = JwkEcKey::from_encoded_point::<NistP256>(&point).unwrap();
    let jwk = JwkEc { key, kid };
    serde_json::to_string(&jwk).unwrap()
}
