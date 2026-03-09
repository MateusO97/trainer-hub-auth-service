package com.trainerhub.auth.security

import com.trainerhub.auth.config.JwtProperties
import com.trainerhub.auth.entity.UserEntity
import com.trainerhub.auth.entity.UserRole
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
}
