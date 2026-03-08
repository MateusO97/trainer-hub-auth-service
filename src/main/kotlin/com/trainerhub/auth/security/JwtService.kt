package com.trainerhub.auth.security

import com.trainerhub.auth.config.JwtProperties
import com.trainerhub.auth.entity.UserEntity
import com.trainerhub.auth.entity.UserRole
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import jakarta.annotation.PostConstruct
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.time.Instant
import java.util.Base64
import java.util.Date
import java.util.UUID
import org.springframework.stereotype.Service

@Service
class JwtService(
    private val jwtProperties: JwtProperties,
) {
    private lateinit var keyPair: KeyPair

    @PostConstruct
    fun init() {
        val keyGenerator = KeyPairGenerator.getInstance("RSA")
        keyGenerator.initialize(2048)
        keyPair = keyGenerator.generateKeyPair()
    }

    fun generateAccessToken(user: UserEntity): String {
        val now = Instant.now()
        val expiry = now.plusSeconds(jwtProperties.expiration)
        val userId = user.id ?: throw IllegalStateException("User id must be present to issue token")

        return Jwts
            .builder()
            .setId(UUID.randomUUID().toString())
            .setSubject(userId.toString())
            .setIssuer(jwtProperties.issuer)
            .setIssuedAt(Date.from(now))
            .setExpiration(Date.from(expiry))
            .claim("email", user.email)
            .claim("role", user.role.name)
            .signWith(keyPair.private, SignatureAlgorithm.RS256)
            .compact()
    }

    fun parseClaims(token: String): Claims =
        Jwts
            .parser()
            .setSigningKey(keyPair.public)
            .build()
            .parseClaimsJws(token)
            .body

    fun getUserId(token: String): UUID = UUID.fromString(parseClaims(token).subject)

    fun getRole(token: String): UserRole = UserRole.valueOf(parseClaims(token)["role", String::class.java])

    fun getEmail(token: String): String = parseClaims(token)["email", String::class.java]

    fun getJti(token: String): String = parseClaims(token).id

    fun getExpiration(token: String): Instant = parseClaims(token).expiration.toInstant()

    fun validate(token: String): Boolean =
        try {
            parseClaims(token)
            true
        } catch (_: Exception) {
            false
        }

    fun getPublicKeyPem(): String {
        val encoded = Base64.getEncoder().encodeToString(keyPair.public.encoded)
        return "-----BEGIN PUBLIC KEY-----\n$encoded\n-----END PUBLIC KEY-----"
    }
}
