package com.trainerhub.auth.service

import com.trainerhub.auth.config.JwtProperties
import com.trainerhub.auth.config.OAuthVerifierFactory
import com.trainerhub.auth.entity.UserEntity
import com.trainerhub.auth.entity.UserRole
import com.trainerhub.auth.exception.UnauthorizedException
import com.trainerhub.auth.repository.OAuthTokenRepository
import com.trainerhub.auth.repository.PasswordResetTokenRepository
import com.trainerhub.auth.repository.RefreshTokenRepository
import com.trainerhub.auth.repository.UserRepository
import com.trainerhub.auth.security.JwtService
import com.trainerhub.auth.security.TokenBlacklistService
import io.mockk.every
import io.mockk.mockk
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder

class AuthServiceTest {
    private val userRepository = mockk<UserRepository>()
    private val refreshTokenRepository = mockk<RefreshTokenRepository>(relaxed = true)
    private val passwordResetTokenRepository = mockk<PasswordResetTokenRepository>(relaxed = true)
    private val oauthTokenRepository = mockk<OAuthTokenRepository>(relaxed = true)
    private val jwtService = JwtService(JwtProperties())
    private val tokenBlacklistService = mockk<TokenBlacklistService>(relaxed = true)
    private val passwordEncoder = BCryptPasswordEncoder(12)
    private val loginAttemptService = LoginAttemptService()
    private val auditLogService = mockk<AuditLogService>(relaxed = true)
    private val oAuthVerifierFactory = mockk<OAuthVerifierFactory>(relaxed = true)

    private val authService =
        AuthService(
            userRepository = userRepository,
            refreshTokenRepository = refreshTokenRepository,
            passwordResetTokenRepository = passwordResetTokenRepository,
            oauthTokenRepository = oauthTokenRepository,
            jwtService = jwtService,
            jwtProperties = JwtProperties(),
            tokenBlacklistService = tokenBlacklistService,
            passwordEncoder = passwordEncoder,
            loginAttemptService = loginAttemptService,
            auditLogService = auditLogService,
            oAuthVerifierFactory = oAuthVerifierFactory,
        )

    init {
        jwtService.init()
    }

    @Test
    fun `login should throw unauthorized on invalid credentials`() {
        every { userRepository.findByEmail("notfound@test.com") } returns null

        assertThrows(UnauthorizedException::class.java) {
            authService.login("notfound@test.com", "Password123", "127.0.0.1", "test")
        }
    }

    @Test
    fun `login should return token pair for valid user`() {
        val user =
            UserEntity(
                id = UUID.randomUUID(),
                email = "valid@test.com",
                passwordHash = passwordEncoder.encode("Password123"),
                role = UserRole.USER,
            )

        every { userRepository.findByEmail("valid@test.com") } returns user
        every { userRepository.save(any()) } answers { firstArg() }
        every { refreshTokenRepository.save(any()) } answers { firstArg() }

        val response = authService.login("valid@test.com", "Password123", "127.0.0.1", "test")

        assertNotNull(response.accessToken)
        assertNotNull(response.refreshToken)
    }
}
