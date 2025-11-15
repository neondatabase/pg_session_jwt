# Contributing

You will need to have `pgrx` installed. First make sure that you have [system
dependencies required by
pgrx](https://github.com/pgcentralfoundation/pgrx#system-requirements).

Now you can install `cargo-pgrx` but make sure to install the same version
that's used by this extension:
```sh
cargo install --locked --version 0.12.6 cargo-pgrx
```

Let's initialize pgrx.
```sh
cargo pgrx init
```

## How to run the extension locally

It's time to run `pg_session_jwt` locally. Please note that `pg_session_jwt.jwk`
parameter MUST be set when new connection is created (for more details please
refer to the README file).
```sh
export PGOPTIONS="-c pg_session_jwt.jwk=$MY_JWK"

cargo pgrx run pg16
```

Eventually you will be logged into postgres so now you can run:
```sql
CREATE EXTENSION pg_session_jwt;
```

Now you can explore available functions with
```sql
\dx auth.*
```

If you introduce new function make sure to reload the extension with
```sql
DROP EXTENSION pg_session_jwt;
CREATE EXTENSION pg_session_jwt;
```

## Before sending a PR

### Setup pre-commit hooks (recommended)

```sh
python -m venv .venv
source .venv/bin/activate
pip install pre-commit
pre-commit install
```

If you're using VSCode/Cursor we recommend you to use directly the `rust-analyzer` extension to run the checks with clippy.
```jsonc
{
    "rust-analyzer.check.command": "clippy"
}
```

### Manual linting
```sh
cargo fmt --all
cargo clippy -p pg_session_jwt -- -D warnings
```

### Run tests
```sh
cargo test
```
