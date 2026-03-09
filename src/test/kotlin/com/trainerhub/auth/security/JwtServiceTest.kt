package com.trainerhub.auth.security

import com.trainerhub.auth.config.JwtProperties
import com.trainerhub.auth.entity.UserEntity
import com.trainerhub.auth.entity.UserRole
import java.security.KeyPairGenerator
import java.util.Base64
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class JwtServiceTest {
    @Test
    fun `should generate and validate access token`() {
        val jwtService =
            JwtService(JwtProperties(expiration = 3600, refreshExpiration = 604800, issuer = "test-issuer"))
        jwtService.init()

        val user =
            UserEntity(
                id = UUID.randomUUID(),
                email = "user@test.com",
                role = UserRole.USER,
            )

        val token = jwtService.generateAccessToken(user)

        assertTrue(jwtService.validate(token))
        assertEquals(user.id, jwtService.getUserId(token))
        assertEquals(user.email, jwtService.getEmail(token))
        assertEquals(UserRole.USER, jwtService.getRole(token))
    }

    @Test
    fun `should load rsa keys from configured pem`() {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val publicPem =
            "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getEncoder().encodeToString(keyPair.public.encoded) +
                "\n-----END PUBLIC KEY-----"
        val privatePem =
            "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getEncoder().encodeToString(keyPair.private.encoded) +
                "\n-----END PRIVATE KEY-----"

        val jwtService =
            JwtService(
                JwtProperties(
                    expiration = 3600,
                    refreshExpiration = 604800,
                    issuer = "test-issuer",
                    publicKeyPem = publicPem,
                    privateKeyPem = privatePem,
                    allowGeneratedKeys = false,
                ),
            )
        jwtService.init()

        val user =
            UserEntity(
                id = UUID.randomUUID(),
                email = "user@test.com",
                role = UserRole.USER,
            )

        val token = jwtService.generateAccessToken(user)
        assertTrue(jwtService.validate(token))
        assertEquals(user.id, jwtService.getUserId(token))
    }
}
