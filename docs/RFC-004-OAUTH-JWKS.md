# RFC-004: OAuth Token Verification with JWKS

**Status:** Proposed  
**Date:** 2026-03-08  
**Supersedes:** DefaultOAuthTokenVerifier stub implementation

## Problem Statement

The current OAuth token verification implementation (`DefaultOAuthTokenVerifier`) is a stub that accepts any token without validating:
- Token signature against provider's public keys
- Standard JWT claims (exp, iss, aud, iat)
- Email verification status

**Security Impact (CRITICAL):** Any attacker can forge OAuth tokens and login as any user.

## Solution Overview

Implement real JWKS (JSON Web Key Set) validation for both Google and Apple OAuth providers with:
1. Fetch and cache JWKS from official provider endpoints
2. Validate token signature against provider's public key
3. Validate all critical claims (issuer, audience, expiration, etc.)
4. Cache keys with TTL for performance

## Detailed Design

### Architecture

```
OAuthVerifierFactory (Strategy Pattern)
├── GoogleOAuthTokenVerifier
│   └── Fetches JWKS from: https://www.googleapis.com/oauth2/v3/certs
└── AppleOAuthTokenVerifier
    └── Fetches JWKS from: https://appleid.apple.com/auth/keys
```

### Google OAuth Validation Flow

1. **Extract KID (Key ID)** from JWT header
2. **Fetch Google JWKS** (with caching, TTL = 1 hour)
3. **Build RSA Public Key** from JWK (n, e components)
4. **Verify Signature** using RS256 algorithm
5. **Validate Claims:**
   - `exp` - Token must not be expired
   - `iss` - Must be `https://accounts.google.com`
   - `aud` - Must match configured GOOGLE_CLIENT_ID
   - `email` - Required and extracted
   - `email_verified` - Recommended to be true
   - `iat` - Issued at must not be in future (prevents clock skew > 60s)

### Apple OAuth Validation Flow

Similar to Google, with differences:
- JWKS URL: `https://appleid.apple.com/auth/keys`
- Issuer: `https://appleid.apple.com`
- Audience: Must match configured APPLE_CLIENT_ID (e.g., app bundle ID or service ID)
- Email: May be optional (included in request body instead of token)
- Nonce: If present, should be validated against stored nonce to prevent replay attacks

## Performance Considerations

### JWKS Caching Strategy

```
Cache Hit (Kid found in memory, TTL valid)
    └── Return key immediately (99% of requests)

Cache Miss (New key or TTL expired)
    └── Fetch fresh JWKS from provider
    └── Parse and cache all keys
    └── Set TTL = 1 hour
    └── Return requested key
```

**Why 1 hour TTL?**
- Google/Apple rarely rotate keys (typically monthly)
- 1 hour provides good balance between freshness and cache efficiency
- Keys are fetched on-demand only when unknown KID encountered
- Failed fetches fallthrough to cached keys gracefully

### HTTP Client Configuration

- Connection Timeout: 5 seconds
- Read Timeout: 5 seconds
- User-Agent header: Identifies traffic to providers
- Automatic retry on network failure (via fallback to cached keys)

## Security Considerations

### Signature Validation
- **Issue:** JWKS endpoint could be compromised
- **Mitigation:** Use HTTPS with certificate pinning (future enhancement)
- **Risk Level:** Medium (assumes GitHub/Google/Apple infrastructure integrity)

### Audience Claim Validation
- **Issue:** Validating audience prevents tokens issued for other apps being used
- **Configuration:** Must set GOOGLE_CLIENT_ID and APPLE_CLIENT_ID environment variables
- **Validation:**
  ```kotlin
  if (aud != configuredClientId) {
      throw UnauthorizedException("Invalid audience")
  }
  ```

### Issuer Claim Validation
- **Issue:** Tokens with spoofed issuer could bypass our system
- **Mitigation:** Hardcoded check for official issuer URLs
- **Validation:** Performed in `validateClaims()` for both providers

### Expiration Validation
- **Issue:** Expired tokens could still be used
- **Mitigation:** Strict expiration check: `if (expirationTime.isBefore(now)) throw`
- **Clock Skew:** Allow 60 seconds of clock skew for issued-at time (`iat`)

## Architectural Decisions

### 1. Strategy Pattern (OAuthVerifierFactory)
- **Rationale:** Clean extension point for new providers (Microsoft, GitHub, etc.)
- **Alternative:** if/else in AuthService - rejected (violates OCP)
- **Impact:** Easy to add providers without modifying AuthService

### 2. HTTP Client for JWKS Fetch
- **Rationale:** Official providers publish JWKs at `https://.../.well-known/json`
- **Alternative:** Package keys in binary - rejected (painful key rotation)
- **Impact:** 5-10ms fetch time, cached to minimize real impact

### 3. ConcurrentHashMap for Local Cache
- **Rationale:** Memory-efficient, thread-safe, simple TTL tracking
- **Alternative:** Distributed cache (Redis) - rejected (adds complexity)
- **Impact:** Lost cache on restart (acceptable, just fetches again on demand)

## Testing Strategy

### Unit Tests
```
GoogleOAuthTokenVerifierTest
├── Valid token with all claims
├── Expired token (exp < now)
├── Invalid signature (tampered payload)
├── Invalid issuer (wrong iss claim)
├── Invalid audience (aud != configured)
├── Missing email claim
├── Unverified email (email_verified = false)
└── Future issued-at (iat > now + 60s)

AppleOAuthTokenVerifierTest
├── Valid token
├── Missing nonce claim
└── Email extraction edge cases
```

**Note:** Tests use mocked HTTP client to return synthetic JWKS to avoid external dependencies.

### Integration Tests
```
AuthControllerIntegrationTest
├── GET /auth/oauth/{provider} with valid token
├── GET /auth/oauth/{provider} with invalid token
├── GET /auth/oauth/{provider} creates new user on first login
└── GET /auth/oauth/{provider} links to existing user on subsequent login
```

### Manual Testing (Using Real Tokens)
1. Configure GOOGLE_CLIENT_ID env var
2. Get real ID token from Google OAuth playground
3. Call POST /api/v1/auth/oauth/google with token
4. Verify user is created/logged in

## Rollout Plan

### Phase 1: Implement (Current)
- [ ] Implement GoogleOAuthTokenVerifier
- [ ] Implement AppleOAuthTokenVerifier
- [ ] Create OAuthVerifierFactory
- [ ] Update AuthService to use factory
- [ ] Add unit tests
- [ ] Update integration tests

### Phase 2: Validation (Optional)
- [ ] Manual testing with real tokens
- [ ] Load testing (verify JWKS fetch doesn't bottleneck)
- [ ] Security review

### Phase 3: Deployment
- [ ] Set GOOGLE_CLIENT_ID and APPLE_CLIENT_ID env vars
- [ ] Deploy to staging
- [ ] Deploy to production

## Fallback/Rollback

**If provider JWKS endpoint is unavailable:**
- First attempt: Use cached key (if available)
- Second attempt: Throw UnauthorizedException
- Result: OAuth login fails, but regular email/password login continues working

**No rollback needed:** This is a pure security enhancement with stub being removed.

## Metrics to Monitor

1. **JWKS Cache Hit Rate** - Target: > 99%
2. **Token Verification Success Rate** - Target: 99.9% (normal deviation < 0.1%)
3. **JWKS Fetch Latency** - Target: < 100ms p95
4. **Validation Rejection Rate** - Target: Baseline + suspect alerts

## Future Enhancements

1. **Certificate Pinning** - Prevent MITM on JWKS fetch
2. **Multi-Provider Federation** - Support Microsoft, GitHub, custom OIDC
3. **Nonce Validation** - Replay attack prevention for Apple
4. **Token Introspection** - Call provider endpoint to revoke tokens
5. **Distributed Cache** - Redis-backed JWKS cache for multi-instance deployments
6. **Mock JWKs Provider** - Test fixture for full OAuth flow

## References

- Google OpenID Connect: https://developers.google.com/identity/protocols/oauth2/openid-connect
- Apple Sign In: https://developer.apple.com/sign-in-with-apple/
- JWT Best Practices: https://tools.ietf.org/html/rfc8949
- JWKS Spec: https://tools.ietf.org/html/rfc7517
