# Requirements Specification - Auth Service

**Version**: 1.0  
**Date**: March 8, 2026  
**Status**: ✅ Approved for Implementation  
**Owner**: Backend Team Lead

---

## Overview

The Auth Service is the **critical path service** for Trainer Hub Phase 2. All other services depend on it for authentication and authorization.

**Priority**: CRITICAL  
**Dependencies**: None (Wave 1, can start immediately)  
**Estimated Duration**: 2 weeks (March 8 - March 22, 2026)

---

## Functional Requirements

### FR-001: Email + Password Authentication

**Priority**: CRITICAL  
**Complexity**: Medium  

#### Description
Users can authenticate using email and password credentials.

#### Acceptance Criteria
- [ ] `POST /api/v1/auth/login` endpoint accepts email + password
- [ ] Email validation (RFC 5322 format)
- [ ] Password hashed with bcrypt (cost: 12)
- [ ] Returns JWT access token (1h validity) + refresh token (7d validity)
- [ ] Returns user object (id, email, firstName, lastName, role)
- [ ] Returns 401 for invalid credentials
- [ ] Returns 400 for missing/invalid fields
- [ ] Rate limiting: max 5 failed attempts per IP per 15min
- [ ] Account lockout after 10 failed attempts (24h duration)
- [ ] Audit log for all login attempts (success + failure)

#### Test Cases
1. **Happy path**: Valid email + password → 200 + tokens
2. **Invalid password**: Wrong password → 401 + error message
3. **Invalid email**: Non-existent email → 401 (no enumeration)
4. **Missing fields**: No password → 400 + validation error
5. **Brute force**: 6th attempt within 15min → 429 + retry-after header
6. **Locked account**: 11th failed attempt → 403 + locked message

---

### FR-002: JWT Token Generation

**Priority**: CRITICAL  
**Complexity**: High  

#### Description
Generate secure JWT tokens for authenticated users.

#### Acceptance Criteria

**Access Token**:
- [ ] Validity: 1 hour
- [ ] Algorithm: RS256 (RSA signature)
- [ ] Payload: `{ sub: userId, email: string, role: string, iat: timestamp, exp: timestamp }`
- [ ] Signed with private RSA key (2048-bit)
- [ ] Verifiable by other services with public key

**Refresh Token**:
- [ ] Validity: 7 days
- [ ] Stored in PostgreSQL (`refresh_tokens` table)
- [ ] Single-use (invalidated after refresh)
- [ ] UUID format (cryptographically secure)
- [ ] Linked to user_id (foreign key)
- [ ] Auto-cleanup of expired tokens (daily cron job)

#### Security Requirements
- [ ] RSA keys generated on first run (stored securely)
- [ ] Public key exposed via `GET /api/v1/auth/public-key` (for service-to-service validation)
- [ ] No sensitive data in JWT payload (no passwords, only IDs)
- [ ] Token signature verification on every request

#### Test Cases
1. **Access token validation**: Decode JWT → verify signature → extract userId
2. **Expired access token**: Token with exp < now → validation fails
3. **Invalid signature**: Tamperedtoken → validation fails
4. **Refresh token reuse**: Same refresh token used twice → 401
5. **Expired refresh token**: Token with expiresAt < now → 401

---

### FR-003: Refresh Token Flow

**Priority**: CRITICAL  
**Complexity**: Medium  

#### Description
Allow users to obtain new access tokens without re-authenticating.

#### Acceptance Criteria
- [ ] `POST /api/v1/auth/refresh` endpoint accepts refresh token
- [ ] Validates refresh token exists in database
- [ ] Checks not expired (`expiresAt > NOW()`)
- [ ] Checks not revoked (`revokedAt IS NULL`)
- [ ] Generates new access token
- [ ] Generates new refresh token (rotate)
- [ ] Invalidates old refresh token (set `revokedAt`)
- [ ] Returns new token pair
- [ ] Returns 401 if token invalid/expired/revoked

#### Test Cases
1. **Happy path**: Valid refresh token → new access + refresh tokens
2. **Expired token**: expiresAt < now → 401
3. **Revoked token**: revokedAt is not null → 401
4. **Non-existent token**: Random UUID → 401
5. **Token rotation**: Old refresh token not reusable after refresh

---

### FR-004: OAuth2 Integration (Google)

**Priority**: HIGH  
**Complexity**: High  

#### Description
Users can sign in with their Google account.

#### Acceptance Criteria
- [ ] `POST /api/v1/auth/oauth/google` endpoint
- [ ] Accepts Google ID token (from client)
- [ ] Verifies ID token with Google API
- [ ] Extracts user info (email, name, googleUserId)
- [ ] **First login**: Create new user if email not exists
- [ ] **Existing user**: Link Google account to existing user (if email matches)
- [ ] Store OAuth token in `oauth_tokens` table
- [ ] Generate JWT access + refresh tokens
- [ ] Returns same response as email login
- [ ] Returns 400 if ID token invalid
- [ ] Returns 401 if Google verification fails

#### Configuration
- [ ] `GOOGLE_CLIENT_ID` environment variable
- [ ] `GOOGLE_CLIENT_SECRET` environment variable
- [ ] Google OAuth2 API enabled in Google Cloud Console

#### Test Cases
1. **New user**: Google login (first time) → user created + tokens returned
2. **Existing user**: Google login (second time) → tokens returned
3. **Invalid token**: Random string → 400
4. **Expired Google token**: Token with exp < now → 401

---

### FR-005: OAuth2 Integration (Apple)

**Priority**: HIGH  
**Complexity**: High  

#### Description
Users can sign in with their Apple ID.

#### Acceptance Criteria
- [ ] `POST /api/v1/auth/oauth/apple` endpoint
- [ ] Accepts Apple ID token (from client)
- [ ] Verifies ID token with Apple API
- [ ] Extracts user info (email, name, appleUserId)
- [ ] Same logic as Google OAuth (create or link user)
- [ ] Store OAuth token in `oauth_tokens` table
- [ ] Returns JWT access + refresh tokens

#### Configuration
- [ ] `APPLE_CLIENT_ID` environment variable
- [ ] `APPLE_CLIENT_SECRET` environment variable (or key file)
- [ ] Apple Sign In configured in Apple Developer Console

#### Test Cases
(Similar to Google OAuth tests)

---

### FR-006: RBAC (Role-Based Access Control)

**Priority**: CRITICAL  
**Complexity**: Low  

#### Description
Assign roles to users to control access permissions.

#### Roles

| Role | Description | Permissions |
|------|-------------|-------------|
| **USER** | Default role | Basic app access |
| **NUTRITIONIST** | Nutrition professional | View clients' data, create meal plans |
| **TRAINER** | Fitness professional | View clients' progress, assign workouts |
| **ADMIN** | System administrator | All permissions, role management |

#### Acceptance Criteria
- [ ] User created with default role: `USER`
- [ ] Role stored in `users.role` column (VARCHAR enum)
- [ ] JWT payload includes `role` claim
- [ ] Other services validate role from JWT
- [ ] **Admin only**: `PATCH /api/v1/users/{id}/role` to change user role
- [ ] Returns 403 if non-admin tries to change role
- [ ] Audit log for role changes

#### Validation Rules
- [ ] Role must be one of: USER, NUTRITIONIST, TRAINER, ADMIN
- [ ] Role cannot be changed via signup/login (only admin endpoint)
- [ ] Role change requires admin JWT token

#### Test Cases
1. **Default role**: New user signup → role = USER
2. **Role in JWT**: Login → JWT contains role claim
3. **Admin change role**: Admin changes user role → success + audit log
4. **Non-admin change role**: USER tries to change role → 403

---

### FR-007: Password Reset Flow

**Priority**: HIGH  
**Complexity**: Medium  

#### Description
Users can reset forgotten passwords via email.

#### Acceptance Criteria

**Request Reset**:
- [ ] `POST /api/v1/auth/password-reset` endpoint
- [ ] Accepts email address
- [ ] Generates secure reset token (UUID v4)
- [ ] Stores token in database with 1h expiration
- [ ] Sends email with reset link (via Notification Service)
- [ ] Returns 200 even if email doesn't exist (no enumeration)

**Confirm Reset**:
- [ ] `POST /api/v1/auth/password-reset-confirm` endpoint
- [ ] Accepts reset token + new password
- [ ] Validates token exists and not expired
- [ ] Validates new password strength
- [ ] Updates `users.password_hash`
- [ ] Invalidates reset token
- [ ] Revokes all refresh tokens for user (force re-login)
- [ ] Returns 200 on success
- [ ] Returns 400 if token invalid/expired

#### Security Requirements
- [ ] Reset token: cryptographically secure random (UUID v4)
- [ ] Token single-use (deleted after consumption)
- [ ] Email link format: `https://app.trainerhub.com/reset-password?token={token}`
- [ ] No user info in error messages (avoiding enumeration)

#### Test Cases
1. **Happy path**: Request reset → receive email → confirm with token → password updated
2. **Expired token**: Token with expiresAt < now → 400
3. **Invalid token**: Random UUID → 400
4. **Token reuse**: Same token used twice → 400
5. **Weak password**: Password "123456" → 400 + validation error

---

### FR-008: Token Validation

**Priority**: CRITICAL  
**Complexity**: Low  

#### Description
Other services can validate JWT tokens.

#### Acceptance Criteria
- [ ] `POST /api/v1/auth/validate-token` endpoint
- [ ] Accepts Authorization header with Bearer token
- [ ] Validates JWT signature (no database call)
- [ ] Checks expiration (`exp` claim)
- [ ] Checks token not in blacklist (Redis lookup)
- [ ] Returns `{ valid: true, user: UserDTO }` if valid
- [ ] Returns `{ valid: false, error: string }` if invalid
- [ ] Returns 200 always (not 401, to avoid service failures)

#### Performance Requirements
- [ ] Response time: < 50ms (p95)
- [ ] Redis cache for blacklist (O(1) lookup)
- [ ] No database queries (JWT validation is stateless)

#### Test Cases
1. **Valid token**: Recent token → valid: true
2. **Expired token**: exp < now → valid: false
3. **Blacklisted token**: Token in Redis blacklist → valid: false
4. **Invalid signature**: Tampered token → valid: false

---

### FR-009: Logout

**Priority**: MEDIUM  
**Complexity**: Low  

#### Description
Users can invalidate their tokens.

#### Acceptance Criteria
- [ ] `POST /api/v1/auth/logout` endpoint
- [ ] Accepts Authorization header with Bearer token
- [ ] Extracts userId from JWT
- [ ] Revokes all refresh tokens for user (set `revokedAt`)
- [ ] Adds access token to Redis blacklist (until expiration)
- [ ] Returns 204 No Content
- [ ] Returns 401 if token invalid

#### Implementation Details
- [ ] Redis key format: `blacklist:{jti}` (JWT ID claim)
- [ ] TTL: remaining time until token expiration
- [ ] Cleanup: Redis auto-expires keys

#### Test Cases
1. **Happy path**: Logout → refresh tokens revoked + access token blacklisted
2. **Token reuse**: Use access token after logout → 401
3. **No header**: Request without Authorization → 401

---

### FR-010: Current User Info

**Priority**: MEDIUM  
**Complexity**: Low  

#### Description
Retrieve authenticated user's information.

#### Acceptance Criteria
- [ ] `GET /api/v1/auth/me` endpoint
- [ ] Requires Authorization header
- [ ] Extracts userId from JWT
- [ ] Fetches user from database
- [ ] Returns user DTO (id, email, firstName, lastName, role, createdAt)
- [ ] Returns 401 if token invalid
- [ ] Returns 404 if user deleted (but token still valid)

#### Test Cases
1. **Happy path**: Valid token → user info returned
2. **Expired token**: exp < now → 401
3. **Deleted user**: Token valid but user doesn't exist → 404

---

### FR-011: Audit Logging

**Priority**: MEDIUM  
**Complexity**: Low  

#### Description
Log all authentication-related events for security monitoring.

#### Events to Log

| Event | Trigger | Data |
|-------|---------|------|
| `LOGIN_SUCCESS` | Successful login | userId, ipAddress, userAgent |
| `LOGIN_FAILURE` | Failed login | email, ipAddress, userAgent, reason |
| `TOKEN_REFRESH` | Refresh token used | userId, ipAddress |
| `LOGOUT` | User logout | userId, ipAddress |
| `PASSWORD_RESET_REQUESTED` | Reset email sent | userId, ipAddress |
| `PASSWORD_RESET_COMPLETED` | Password updated | userId, ipAddress |
| `ROLE_CHANGED` | Admin changed role | userId, adminId, oldRole, newRole |
| `ACCOUNT_LOCKED` | Too many failed attempts | userId, ipAddress |

#### Acceptance Criteria
- [ ] All events stored in `audit_log` table
- [ ] Timestamp (createdAt) for every event
- [ ] IP address extracted from `X-Forwarded-For` or `RemoteAddr`
- [ ] User-Agent extracted from header
- [ ] Details stored as JSONB (flexible schema)
- [ ] Audit log API: `GET /api/v1/admin/audit-log` (admin only)
- [ ] Pagination + filtering by userId, action, dateRange

#### Test Cases
1. **Login success**: Event logged with correct data
2. **Login failure**: Event logged with email (even if user doesn't exist)
3. **Admin audit access**: Admin can view logs
4. **Non-admin audit access**: USER cannot view logs → 403

---

## Non-Functional Requirements

### NFR-001: Performance

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Response Time (p95)** | < 200ms | All endpoints |
| **Response Time (p99)** | < 500ms | All endpoints |
| **Throughput** | > 100 req/s | Single instance |
| **Database Queries** | < 3 queries per request | Optimized JPA |

### NFR-002: Security

- [ ] HTTPS enforced in production (TLS 1.3)
- [ ] CORS configured for frontend origins only
- [ ] SQL injection prevention (parameterized queries)
- [ ] XSS prevention (input sanitization)
- [ ] CSRF protection (stateless JWT, no cookies)
- [ ] Sensitive data encrypted in database (password_hash only)
- [ ] No plaintext passwords in logs/errors
- [ ] Rate limiting: 100 req/min per user
- [ ] Brute force protection: 5 failed attempts per IP per 15min

### NFR-003: Reliability

- [ ] Uptime: 99.9% (excluding planned maintenance)
- [ ] Circuit breaker for external APIs (Google, Apple)
- [ ] Graceful degradation (OAuth unavailable → email login still works)
- [ ] Database connection pooling (HikariCP)
- [ ] Connection timeout: 5s
- [ ] Query timeout: 10s

### NFR-004: Scalability

- [ ] Horizontal scaling: supports multiple instances
- [ ] Stateless design (no session state in memory)
- [ ] Redis for distributed cache
- [ ] Database read replicas (future)

### NFR-005: Observability

- [ ] Structured logging (JSON format)
- [ ] Log levels: ERROR, WARN, INFO, DEBUG
- [ ] Metrics: Prometheus format exposed at `/actuator/prometheus`
- [ ] Health check: `GET /actuator/health`
- [ ] Request tracing: `X-Request-Id` header propagation

### NFR-006: Testing

| Type | Coverage | Enforcement |
|------|----------|-------------|
| **Unit Tests** | ≥ 80% | CI/CD blocks PR |
| **Integration Tests** | ≥ 70% | CI/CD warning |
| **E2E Tests** | ≥ 50% | Manual run |

- [ ] TestContainers for integration tests (real PostgreSQL + Redis)
- [ ] Mockito for unit tests
- [ ] JUnit 5 test framework
- [ ] Test fixtures for common scenarios

### NFR-007: Documentation

- [ ] OpenAPI 3.0 specification (auto-generated from controllers)
- [ ] Swagger UI available at `/swagger-ui.html` (dev only)
- [ ] README.md with quick start guide
- [ ] API.md with complete endpoint documentation
- [ ] ARCHITECTURE.md with design decisions
- [ ] DEPLOYMENT.md with deployment steps

---

## Dependencies

### Internal Dependencies
- None (Auth Service is the foundation, no internal dependencies)

### External Dependencies

| Service | Purpose | Fallback |
|---------|---------|----------|
| **PostgreSQL** | Primary database | None (critical) |
| **Redis** | Token blacklist cache | Graceful degradation (validate without cache) |
| **Google OAuth API** | Google Sign-In | Email login still works |
| **Apple OAuth API** | Apple Sign-In | Email login still works |
| **Notification Service** | Password reset emails | Queue emails (async) |

---

## Implementation Phases

### Week 1: Core Authentication (March 8-14)

**Days 1-2**: Setup & Schema
- [ ] Project scaffolding (Spring Boot + Gradle)
- [ ] Database schema (Flyway migrations)
- [ ] Docker Compose (PostgreSQL + Redis)
- [ ] Basic configuration (application.yml)

**Days 3-4**: Email Login
- [ ] `POST /api/v1/auth/login` implementation
- [ ] JWT generation (access + refresh tokens)
- [ ] Password hashing (bcrypt)
- [ ] Basic tests

**Day 5**: Refresh Token Flow
- [ ] `POST /api/v1/auth/refresh` implementation
- [ ] Token rotation logic
- [ ] Integration tests with TestContainers

### Week 2: OAuth2 & Security (March 15-22)

**Days 1-2**: OAuth2
- [ ] Google OAuth2 implementation
- [ ] Apple OAuth2 implementation
- [ ] Account linking logic

**Day 3**: RBAC & Audit
- [ ] Role assignment
- [ ] Audit logging service
- [ ] Admin endpoints

**Days 4-5**: Security & Deployment
- [ ] Rate limiting
- [ ] Password reset flow
- [ ] Security hardening
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Docker image
- [ ] API documentation

---

## Success Criteria

✅ All functional requirements implemented and tested  
✅ Code coverage ≥ 80%  
✅ All endpoints working locally  
✅ Docker image builds successfully  
✅ CI/CD pipeline passing  
✅ API documentation complete  
✅ PR approved by 2+ reviewers  

---

## References

- [Trainer Hub Docs](https://github.com/MateusO97/trainer-hub-docs)
- [FASE-2 Plan](https://github.com/MateusO97/trainer-hub-docs/blob/master/docs/FASE-2-PLAN.md)
- [Auth Service Spec](https://github.com/MateusO97/trainer-hub-docs/blob/master/docs/FASE-2/AUTH-SERVICE.md)
- [Coding Standards](https://github.com/MateusO97/trainer-hub-docs/blob/master/docs/INFRASTRUCTURE/CODING-STANDARDS.md)

---

**Last Updated**: March 8, 2026  
**Next Review**: After Week 1 completion
