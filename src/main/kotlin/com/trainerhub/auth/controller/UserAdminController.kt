package com.trainerhub.auth.controller

import com.trainerhub.auth.dto.PublicUserResponse
import com.trainerhub.auth.dto.UpdateRoleRequest
import com.trainerhub.auth.security.JwtService
import com.trainerhub.auth.service.AuthService
import jakarta.validation.Valid
import java.util.UUID
import org.springframework.web.bind.annotation.PatchMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/users")
class UserAdminController(
    private val authService: AuthService,
    private val jwtService: JwtService,
) {
    @PatchMapping("/{userId}/role")
    fun updateRole(
        @PathVariable userId: UUID,
        @Valid @RequestBody request: UpdateRoleRequest,
        @RequestHeader("Authorization") authorizationHeader: String,
    ): PublicUserResponse {
        val token = authorizationHeader.removePrefix("Bearer ").trim()
        val requesterId = jwtService.getUserId(token)
        return authService.updateRole(requesterId, userId, request.role)
    }
}
