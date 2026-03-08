package com.trainerhub.auth.controller

import com.trainerhub.auth.dto.AuthTokensResponse
import com.trainerhub.auth.dto.GenericMessageResponse
import com.trainerhub.auth.dto.LoginRequest
import com.trainerhub.auth.dto.OAuthLoginRequest
import com.trainerhub.auth.dto.PasswordResetConfirmRequest
import com.trainerhub.auth.dto.PasswordResetRequest
import com.trainerhub.auth.dto.PublicUserResponse
import com.trainerhub.auth.dto.RefreshRequest
import com.trainerhub.auth.dto.ValidateTokenResponse
import com.trainerhub.auth.entity.OAuthProvider
import com.trainerhub.auth.security.JwtService
import com.trainerhub.auth.service.AuthService
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Auth", description = "Authentication endpoints")
class AuthController(
    private val authService: AuthService,
    private val jwtService: JwtService,
) {
    @PostMapping("/login")
    @Operation(summary = "Email and password login")
    fun login(
        @Valid @RequestBody request: LoginRequest,
        @RequestHeader(value = "X-Forwarded-For", required = false) ipAddress: String?,
        @RequestHeader(value = "User-Agent", required = false) userAgent: String?,
    ): AuthTokensResponse = authService.login(request.email, request.password, ipAddress, userAgent)

    @PostMapping("/refresh")
    fun refresh(
        @Valid @RequestBody request: RefreshRequest,
        @RequestHeader(value = "X-Forwarded-For", required = false) ipAddress: String?,
        @RequestHeader(value = "User-Agent", required = false) userAgent: String?,
    ): AuthTokensResponse = authService.refresh(request.refreshToken, ipAddress, userAgent)

    @PostMapping("/logout")
    fun logout(
        @RequestHeader("Authorization") authorizationHeader: String,
        @RequestHeader(value = "X-Forwarded-For", required = false) ipAddress: String?,
        @RequestHeader(value = "User-Agent", required = false) userAgent: String?,
    ): ResponseEntity<Void> {
        val token = authorizationHeader.removePrefix("Bearer ").trim()
        authService.logout(token, ipAddress, userAgent)
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build()
    }

    @PostMapping("/validate-token")
    fun validateToken(
        @RequestHeader("Authorization") authorizationHeader: String,
    ): ValidateTokenResponse {
        val token = authorizationHeader.removePrefix("Bearer ").trim()
        return authService.validateToken(token)
    }

    @GetMapping("/me")
    fun me(
        @RequestHeader("Authorization") authorizationHeader: String,
    ): PublicUserResponse {
        val token = authorizationHeader.removePrefix("Bearer ").trim()
        return authService.currentUser(token)
    }

    @PostMapping("/password-reset/request")
    fun passwordResetRequest(
        @Valid @RequestBody request: PasswordResetRequest,
        @RequestHeader(value = "X-Forwarded-For", required = false) ipAddress: String?,
        @RequestHeader(value = "User-Agent", required = false) userAgent: String?,
    ): GenericMessageResponse = authService.requestPasswordReset(request.email, ipAddress, userAgent)

    @PostMapping("/password-reset/confirm")
    fun passwordResetConfirm(
        @Valid @RequestBody request: PasswordResetConfirmRequest,
        @RequestHeader(value = "X-Forwarded-For", required = false) ipAddress: String?,
        @RequestHeader(value = "User-Agent", required = false) userAgent: String?,
    ): GenericMessageResponse =
        authService.confirmPasswordReset(
            request.token,
            request.newPassword,
            ipAddress,
            userAgent,
        )

    @PostMapping("/oauth/google")
    fun googleOAuth(
        @Valid @RequestBody request: OAuthLoginRequest,
        @RequestHeader(value = "X-Forwarded-For", required = false) ipAddress: String?,
        @RequestHeader(value = "User-Agent", required = false) userAgent: String?,
    ): AuthTokensResponse = authService.oauthLogin(OAuthProvider.GOOGLE, request.idToken, ipAddress, userAgent)

    @PostMapping("/oauth/apple")
    fun appleOAuth(
        @Valid @RequestBody request: OAuthLoginRequest,
        @RequestHeader(value = "X-Forwarded-For", required = false) ipAddress: String?,
        @RequestHeader(value = "User-Agent", required = false) userAgent: String?,
    ): AuthTokensResponse = authService.oauthLogin(OAuthProvider.APPLE, request.idToken, ipAddress, userAgent)

    @GetMapping("/public-key")
    fun publicKey(): GenericMessageResponse = GenericMessageResponse(jwtService.getPublicKeyPem())
}
