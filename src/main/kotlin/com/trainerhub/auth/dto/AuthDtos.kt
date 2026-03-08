package com.trainerhub.auth.dto

import com.trainerhub.auth.entity.UserRole
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Pattern
import jakarta.validation.constraints.Size
import java.time.Instant
import java.util.UUID

data class LoginRequest(
    @field:Email @field:NotBlank val email: String,
    @field:NotBlank @field:Size(min = 8, max = 128) val password: String,
)

data class RefreshRequest(
    @field:NotBlank val refreshToken: String,
)

data class PasswordResetRequest(
    @field:Email @field:NotBlank val email: String,
)

data class PasswordResetConfirmRequest(
    @field:NotBlank val token: String,
    @field:NotBlank
    @field:Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d).{8,128}$")
    val newPassword: String,
)

data class OAuthLoginRequest(
    @field:NotBlank val idToken: String,
)

data class UpdateRoleRequest(
    val role: UserRole,
)

data class AuthTokensResponse(
    val accessToken: String,
    val refreshToken: String,
    val tokenType: String = "Bearer",
    val expiresIn: Long,
    val user: PublicUserResponse,
)

data class PublicUserResponse(
    val userId: UUID,
    val email: String,
    val firstName: String?,
    val lastName: String?,
    val role: UserRole,
    val createdAt: Instant,
)

data class ValidateTokenResponse(
    val valid: Boolean,
    val user: TokenUserContext? = null,
    val error: String? = null,
)

data class TokenUserContext(
    val userId: UUID,
    val email: String,
    val role: UserRole,
)

data class GenericMessageResponse(
    val message: String,
)
