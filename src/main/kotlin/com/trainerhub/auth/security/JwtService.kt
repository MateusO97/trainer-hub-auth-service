package com.trainerhub.auth.security

import com.trainerhub.auth.config.JwtProperties
import com.trainerhub.auth.entity.UserEntity
import com.trainerhub.auth.entity.UserRole
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import jakarta.annotation.PostConstruct
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64
import java.util.Date
import java.util.UUID
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service

@Service
class JwtService(
    private val jwtProperties: JwtProperties,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private lateinit var keyPair: KeyPair

    @PostConstruct
    fun init() {
        val configuredPublic = jwtProperties.publicKeyPem?.trim().orEmpty()
        val configuredPrivate = jwtProperties.privateKeyPem?.trim().orEmpty()

        if (configuredPublic.isNotBlank() && configuredPrivate.isNotBlank()) {
            keyPair = loadConfiguredKeyPair(configuredPublic, configuredPrivate)
            logger.info("JWT RSA key pair loaded from configuration")
            return
        }

        if (!jwtProperties.allowGeneratedKeys) {
            throw IllegalStateException(
                "JWT keys are not configured and generated keys are disabled. " +
                    "Set jwt.public-key-pem and jwt.private-key-pem.",
            )
        }

        val keyGenerator = KeyPairGenerator.getInstance("RSA")
        keyGenerator.initialize(2048)
        keyPair = keyGenerator.generateKeyPair()
        logger.warn("JWT RSA key pair generated at startup. Configure persistent PEM keys for production.")
    }

    private fun loadConfiguredKeyPair(
        publicPem: String,
        privatePem: String,
    ): KeyPair {
        val keyFactory = KeyFactory.getInstance("RSA")
        val publicBytes = decodePem(publicPem, "PUBLIC KEY")
        val privateBytes = decodePem(privatePem, "PRIVATE KEY")

        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicBytes)) as RSAPublicKey
        val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(privateBytes)) as RSAPrivateKey
        return KeyPair(publicKey, privateKey)
    }

    private fun decodePem(
        pem: String,
        label: String,
    ): ByteArray {
        val stripped =
            pem
                .replace("-----BEGIN $label-----", "")
                .replace("-----END $label-----", "")
                .replace("\\s".toRegex(), "")
        return Base64.getDecoder().decode(stripped)
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
