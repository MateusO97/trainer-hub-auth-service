package com.trainerhub.auth.controller

import com.fasterxml.jackson.databind.ObjectMapper
import com.trainerhub.auth.dto.LoginRequest
import com.trainerhub.auth.dto.RefreshRequest
import com.trainerhub.auth.entity.UserEntity
import com.trainerhub.auth.entity.UserRole
import com.trainerhub.auth.repository.RefreshTokenRepository
import com.trainerhub.auth.repository.UserRepository
import org.hamcrest.Matchers.notNullValue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.http.MediaType
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthControllerIntegrationTest {
    @Autowired
    private lateinit var mockMvc: MockMvc

    @Autowired
    private lateinit var objectMapper: ObjectMapper

    @Autowired
    private lateinit var userRepository: UserRepository

    @Autowired
    private lateinit var refreshTokenRepository: RefreshTokenRepository

    @Autowired
    private lateinit var passwordEncoder: PasswordEncoder

    @BeforeEach
    fun setup() {
        refreshTokenRepository.deleteAll()
        userRepository.deleteAll()
        userRepository.save(
            UserEntity(
                email = "integration@test.com",
                passwordHash = passwordEncoder.encode("Password123"),
                role = UserRole.USER,
                firstName = "Integration",
                lastName = "User",
            ),
        )
    }

    @Test
    fun `login should return token pair`() {
        val payload = LoginRequest(email = "integration@test.com", password = "Password123")

        mockMvc.perform(
            post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(payload)),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.accessToken", notNullValue()))
            .andExpect(jsonPath("$.refreshToken", notNullValue()))
            .andExpect(jsonPath("$.user.email").value("integration@test.com"))
    }

    @Test
    fun `refresh should rotate refresh token`() {
        val loginPayload = LoginRequest(email = "integration@test.com", password = "Password123")
        val loginResponse =
            mockMvc.perform(
                post("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(loginPayload)),
            ).andReturn().response.contentAsString

        val refreshToken = objectMapper.readTree(loginResponse).get("refreshToken").asText()
        val refreshPayload = RefreshRequest(refreshToken)

        mockMvc.perform(
            post("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(refreshPayload)),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.accessToken", notNullValue()))
            .andExpect(jsonPath("$.refreshToken", notNullValue()))
    }

    @Test
    fun `me should return current user profile`() {
        val loginPayload = LoginRequest(email = "integration@test.com", password = "Password123")
        val loginResponse =
            mockMvc.perform(
                post("/api/v1/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsString(loginPayload)),
            ).andReturn().response.contentAsString

        val accessToken = objectMapper.readTree(loginResponse).get("accessToken").asText()

        mockMvc.perform(
            get("/api/v1/auth/me")
                .header("Authorization", "Bearer $accessToken"),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.email").value("integration@test.com"))
            .andExpect(jsonPath("$.role").value("USER"))
    }
}
