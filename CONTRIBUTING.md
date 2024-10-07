# Contributing

You will need to have `pgrx` installed. First make sure that you have [system
dependencies required by
pgrx](https://github.com/pgcentralfoundation/pgrx#system-requirements).

Now you can install `cargo-pgrx` but make sure to install the same version
that's used by this extension:
```console
cargo install --locked --version 0.11.3 cargo-pgrx
```

Let's initialize pgrx.
```console
cargo pgrx init
```

It's time to run `pg_session_jwt` locally with
```console
cargo pgrx run pg16
```

Eventually you will be logged into postgres so now you can run:
```
CREATE EXTENSION pg_session_jwt;
```
