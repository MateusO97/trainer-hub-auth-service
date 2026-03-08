package com.trainerhub.auth.security

import com.trainerhub.auth.repository.UserRepository
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JwtAuthenticationFilter(
    private val jwtService: JwtService,
    private val tokenBlacklistService: TokenBlacklistService,
    private val userRepository: UserRepository,
) : OncePerRequestFilter() {
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        val authHeader = request.getHeader("Authorization")
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response)
            return
        }

        val token = authHeader.removePrefix("Bearer ").trim()
        if (!jwtService.validate(token)) {
            filterChain.doFilter(request, response)
            return
        }

        val jti = jwtService.getJti(token)
        if (tokenBlacklistService.isBlacklistedByJti(jti)) {
            filterChain.doFilter(request, response)
            return
        }

        val userId = jwtService.getUserId(token)
        val role = jwtService.getRole(token)
        val user = userRepository.findById(userId).orElse(null)
        if (user != null) {
            val auth =
                UsernamePasswordAuthenticationToken(
                    user.id.toString(),
                    null,
                    listOf(SimpleGrantedAuthority("ROLE_${role.name}")),
                )
            SecurityContextHolder.getContext().authentication = auth
        }

        filterChain.doFilter(request, response)
    }
}
