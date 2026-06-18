# Regression Tests for pg_session_jwt

This directory contains regression tests for the pg_session_jwt extension.

## Running the Tests

To run the regression tests for pg_session_jwt:

1. Install the extension in your PostgreSQL instance:
   ```
   cargo pgrx install
   ```

2. Run the regression tests:
   ```
   make installcheck
   ```

The regression tests use pg_regress to test the extension's functionality.

## Test Structure

- `sql/`: Contains SQL test files that are executed by pg_regress
- `expected/`: Contains expected output files for each test
- `generate_jwt.py`: Helper script to generate valid JWTs and JWKs for testing

## Generating Test JWTs and JWKs

You can use the included helper script to generate valid JWTs and JWKs for testing:

```
./generate_jwt.py --subject test_user --jti 1 --nbf $(date +%s) --exp $(($(date +%s) + 3600))
```

This will output a JWT and JWK that can be used in the tests.
