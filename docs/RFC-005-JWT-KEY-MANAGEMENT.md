# RFC-005: JWT Key Management for Production

## Context
`JwtService` used to generate a new RSA key pair on every startup. This invalidates previously issued tokens after restart and is unsafe for production operations.

## Decision
Use externally provided PEM keys in production and allow ephemeral generated keys only for development/test.

## Configuration
- `jwt.public-key-pem` from `JWT_PUBLIC_KEY_PEM`
- `jwt.private-key-pem` from `JWT_PRIVATE_KEY_PEM`
- `jwt.allow-generated-keys` from `JWT_ALLOW_GENERATED_KEYS`

Production profile (`application-prod.yml`) sets:
- `jwt.allow-generated-keys: false`

## Behavior
1. If both PEM keys exist, service loads and uses them.
2. If missing and `allow-generated-keys=true`, service generates keys at startup (dev only).
3. If missing and `allow-generated-keys=false`, service fails fast on startup.

## Security Notes
- Persist keys in secret manager (Vault, AWS Secrets Manager, GCP Secret Manager).
- Rotate keys with overlap window and short token TTL.
- Keep private key write access restricted to auth service runtime only.

## Test Coverage
- `JwtServiceTest` includes scenario loading configured PEM keys and validating issued token parsing.
