package com.trainerhub.auth.service

import com.trainerhub.auth.config.JwtProperties
import com.trainerhub.auth.config.OAuthVerifierFactory
import com.trainerhub.auth.dto.AuthTokensResponse
import com.trainerhub.auth.dto.GenericMessageResponse
import com.trainerhub.auth.dto.PublicUserResponse
import com.trainerhub.auth.dto.TokenUserContext
import com.trainerhub.auth.dto.ValidateTokenResponse
import com.trainerhub.auth.entity.AuditAction
import com.trainerhub.auth.entity.OAuthProvider
import com.trainerhub.auth.entity.OAuthTokenEntity
import com.trainerhub.auth.entity.PasswordResetTokenEntity
import com.trainerhub.auth.entity.RefreshTokenEntity
import com.trainerhub.auth.entity.UserEntity
import com.trainerhub.auth.entity.UserRole
import com.trainerhub.auth.exception.BadRequestException
import com.trainerhub.auth.exception.ForbiddenException
import com.trainerhub.auth.exception.LockedException
import com.trainerhub.auth.exception.UnauthorizedException
import com.trainerhub.auth.repository.OAuthTokenRepository
import com.trainerhub.auth.repository.PasswordResetTokenRepository
import com.trainerhub.auth.repository.RefreshTokenRepository
import com.trainerhub.auth.repository.UserRepository
import com.trainerhub.auth.security.JwtService
import com.trainerhub.auth.security.TokenBlacklistService
import java.time.Duration
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class AuthService(
    private val userRepository: UserRepository,
    private val refreshTokenRepository: RefreshTokenRepository,
    private val passwordResetTokenRepository: PasswordResetTokenRepository,
    private val oauthTokenRepository: OAuthTokenRepository,
    private val jwtService: JwtService,
    private val jwtProperties: JwtProperties,
    private val tokenBlacklistService: TokenBlacklistService,
    private val passwordEncoder: PasswordEncoder,
    private val loginAttemptService: LoginAttemptService,
    private val auditLogService: AuditLogService,
    private val oAuthVerifierFactory: OAuthVerifierFactory,
) {
    @Transactional
    fun login(
        email: String,
        password: String,
        ipAddress: String?,
        userAgent: String?,
    ): AuthTokensResponse {
        val normalizedEmail = email.trim().lowercase()
        val ip = ipAddress ?: "unknown"

        if (loginAttemptService.isBlocked(ip)) {
            throw LockedException("Too many failed attempts from this IP")
        }

        val user =
            userRepository.findByEmail(normalizedEmail)
                ?: run {
                    loginAttemptService.onFailedAttempt(ip)
                    auditLogService.log(AuditAction.LOGIN_FAILED, null, ip, userAgent, "unknown-email")
                    throw UnauthorizedException("Invalid credentials")
                }

        if (user.lockedUntil != null && user.lockedUntil!!.isAfter(Instant.now())) {
            throw LockedException("Account is locked")
        }

        val passwordHash = user.passwordHash ?: throw UnauthorizedException("Invalid credentials")
        if (!passwordEncoder.matches(password, passwordHash)) {
            loginAttemptService.onFailedAttempt(ip)
            user.failedLoginAttempts += 1
            if (user.failedLoginAttempts >= 10) {
                user.lockedUntil = Instant.now().plus(24, ChronoUnit.HOURS)
                auditLogService.log(AuditAction.ACCOUNT_LOCKED, user.id, ip, userAgent, "failed-attempts=10")
            }
            userRepository.save(user)
            auditLogService.log(AuditAction.LOGIN_FAILED, user.id, ip, userAgent, "bad-password")
            throw UnauthorizedException("Invalid credentials")
        }

        user.failedLoginAttempts = 0
        user.lockedUntil = null
        user.updatedAt = Instant.now()
        userRepository.save(user)
        loginAttemptService.clear(ip)

        val tokenResponse = issueTokens(user)
        auditLogService.log(AuditAction.LOGIN, user.id, ip, userAgent, "email-login")
        return tokenResponse
    }

    @Transactional
    fun refresh(
        refreshToken: String,
        ipAddress: String?,
        userAgent: String?,
    ): AuthTokensResponse {
        val tokenRecord =
            refreshTokenRepository.findByToken(refreshToken)
                ?: throw UnauthorizedException("Invalid refresh token")

        if (tokenRecord.revokedAt != null || tokenRecord.expiresAt.isBefore(Instant.now())) {
            throw UnauthorizedException("Refresh token expired or revoked")
        }

        tokenRecord.revokedAt = Instant.now()
        refreshTokenRepository.save(tokenRecord)

        val response = issueTokens(tokenRecord.user)
        auditLogService.log(AuditAction.TOKEN_REFRESH, tokenRecord.user.id, ipAddress, userAgent, "refresh-rotated")
        return response
    }

    @Transactional
    fun logout(
        accessToken: String,
        ipAddress: String?,
        userAgent: String?,
    ) {
        if (!jwtService.validate(accessToken)) {
            throw UnauthorizedException("Invalid token")
        }

        val userId = jwtService.getUserId(accessToken)
        val jti = jwtService.getJti(accessToken)
        val exp = jwtService.getExpiration(accessToken)
        val ttl = Duration.between(Instant.now(), exp).seconds

        val user = userRepository.findById(userId).orElseThrow { UnauthorizedException("Invalid user") }
        refreshTokenRepository.revokeAllForUser(user, Instant.now())
        tokenBlacklistService.blacklist(jti, ttl)
        auditLogService.log(AuditAction.LOGOUT, user.id, ipAddress, userAgent, "logout")
    }

    fun validateToken(accessToken: String): ValidateTokenResponse {
        if (!jwtService.validate(accessToken)) {
            return ValidateTokenResponse(valid = false, error = "invalid-signature-or-expired")
        }

        val jti = jwtService.getJti(accessToken)
        if (tokenBlacklistService.isBlacklistedByJti(jti)) {
            return ValidateTokenResponse(valid = false, error = "blacklisted")
        }

        val userId = jwtService.getUserId(accessToken)
        val context =
            TokenUserContext(
                userId = userId,
                email = jwtService.getEmail(accessToken),
                role = jwtService.getRole(accessToken),
            )
        auditLogService.log(AuditAction.TOKEN_VALIDATED, userId, details = "valid")
        return ValidateTokenResponse(valid = true, user = context)
    }

    fun currentUser(accessToken: String): PublicUserResponse {
        if (!jwtService.validate(accessToken)) {
            throw UnauthorizedException("Invalid token")
        }
        val userId = jwtService.getUserId(accessToken)
        val user = userRepository.findById(userId).orElseThrow { UnauthorizedException("User not found") }
        return user.toPublicResponse()
    }

    @Transactional
    fun requestPasswordReset(
        email: String,
        ipAddress: String?,
        userAgent: String?,
    ): GenericMessageResponse {
        val user = userRepository.findByEmail(email.trim().lowercase())
        if (user != null) {
            val token = UUID.randomUUID().toString()
            passwordResetTokenRepository.save(
                PasswordResetTokenEntity(
                    user = user,
                    token = token,
                    expiresAt = Instant.now().plus(1, ChronoUnit.HOURS),
                ),
            )
            auditLogService.log(AuditAction.PASSWORD_RESET_REQUEST, user.id, ipAddress, userAgent, "token-issued")
        }
        return GenericMessageResponse("If the email exists, reset instructions were sent")
    }

    @Transactional
    fun confirmPasswordReset(
        token: String,
        newPassword: String,
        ipAddress: String?,
        userAgent: String?,
    ): GenericMessageResponse {
        val resetToken =
            passwordResetTokenRepository.findByToken(token)
                ?: throw BadRequestException("Invalid reset token")

        if (resetToken.usedAt != null || resetToken.expiresAt.isBefore(Instant.now())) {
            throw BadRequestException("Reset token expired or already used")
        }

        val user = resetToken.user
        user.passwordHash = passwordEncoder.encode(newPassword)
        user.updatedAt = Instant.now()
        userRepository.save(user)

        resetToken.usedAt = Instant.now()
        passwordResetTokenRepository.save(resetToken)

        refreshTokenRepository.revokeAllForUser(user, Instant.now())
        auditLogService.log(AuditAction.PASSWORD_RESET_CONFIRM, user.id, ipAddress, userAgent, "password-updated")
        return GenericMessageResponse("Password reset successful")
    }

    @Transactional
    fun oauthLogin(
        provider: OAuthProvider,
        idToken: String,
        ipAddress: String?,
        userAgent: String?,
    ): AuthTokensResponse {
        val verifier = oAuthVerifierFactory.getVerifier(provider)
        val identity = verifier.verify(provider, idToken)
        val existing = userRepository.findByEmail(identity.email.trim().lowercase())

        val user =
            if (existing != null) {
                existing
            } else {
                userRepository.save(
                    UserEntity(
                        email = identity.email.trim().lowercase(),
                        firstName = identity.firstName,
                        lastName = identity.lastName,
                        role = UserRole.USER,
                        isActive = true,
                    ),
                )
            }

        val oauthToken =
            oauthTokenRepository.findByProviderAndProviderUserId(provider, identity.providerUserId)
                ?: OAuthTokenEntity(
                    user = user,
                    provider = provider,
                    providerUserId = identity.providerUserId,
                )
        oauthToken.user = user
        oauthToken.updatedAt = Instant.now()
        oauthTokenRepository.save(oauthToken)

        auditLogService.log(AuditAction.OAUTH_LOGIN, user.id, ipAddress, userAgent, "provider=${provider.name}")
        return issueTokens(user)
    }

    @Transactional
    fun updateRole(
        requesterId: UUID,
        userId: UUID,
        role: UserRole,
    ): PublicUserResponse {
        val requester = userRepository.findById(requesterId).orElseThrow { ForbiddenException("Requester not found") }
        if (requester.role != UserRole.ADMIN) {
            throw ForbiddenException("Only admin can change roles")
        }

        val user = userRepository.findById(userId).orElseThrow { BadRequestException("User not found") }
        user.role = role
        user.updatedAt = Instant.now()
        val updated = userRepository.save(user)
        auditLogService.log(AuditAction.ROLE_CHANGED, updated.id, details = "newRole=${role.name}")
        return updated.toPublicResponse()
    }

    private fun issueTokens(user: UserEntity): AuthTokensResponse {
        val accessToken = jwtService.generateAccessToken(user)
        val refreshToken = UUID.randomUUID().toString()
        refreshTokenRepository.save(
            RefreshTokenEntity(
                user = user,
                token = refreshToken,
                expiresAt = Instant.now().plusSeconds(jwtProperties.refreshExpiration),
            ),
        )

        return AuthTokensResponse(
            accessToken = accessToken,
            refreshToken = refreshToken,
            expiresIn = jwtProperties.expiration,
            user = user.toPublicResponse(),
        )
    }

    private fun UserEntity.toPublicResponse(): PublicUserResponse =
        PublicUserResponse(
            userId = id ?: throw IllegalStateException("User id must not be null"),
            email = email,
            firstName = firstName,
            lastName = lastName,
            role = role,
            createdAt = createdAt,
        )
}
