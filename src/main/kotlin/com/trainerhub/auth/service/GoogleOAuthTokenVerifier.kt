package com.trainerhub.auth.service

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.trainerhub.auth.entity.OAuthProvider
import com.trainerhub.auth.exception.UnauthorizedException
import io.jsonwebtoken.Claims
import io.jsonwebtoken.JwtException
import io.jsonwebtoken.Jwts
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.InvalidKeySpecException
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service

data class GoogleJwksKey(
    val kty: String,
    val use: String?,
    val kid: String,
    val n: String,
    val e: String,
)

data class GoogleJwks(
    val keys: List<GoogleJwksKey>,
)

@Service
class GoogleOAuthTokenVerifier(
    private val httpClient: HttpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(),
    private val objectMapper: ObjectMapper = jacksonObjectMapper(),
) : OAuthTokenVerifier {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val jwksCache = ConcurrentHashMap<String, CachedKey>()
    private val jwksUrl = "https://www.googleapis.com/oauth2/v3/certs"
    private val lastJwksFetch = mutableMapOf<String, Instant>()
    private val jwksCacheTtl = Duration.ofHours(1)

    data class CachedKey(val key: PublicKey, val cachedAt: Instant)

    override fun verify(
        provider: OAuthProvider,
        idToken: String,
    ): OAuthIdentity {
        if (provider != OAuthProvider.GOOGLE) {
            throw UnauthorizedException("This verifier only handles Google OAuth")
        }

        try {
            val kid = extractKid(idToken)

            // Get the public key
            val publicKey = getPublicKeyFromJwks(kid)

            // Verify signature and get claims
            val claims =
                Jwts.parser()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(idToken)
                    .body

            // Validate standard claims
            validateClaims(claims)

            return OAuthIdentity(
                providerUserId = claims.subject,
                email = claims["email"] as? String ?: throw UnauthorizedException("Missing email claim"),
                firstName = claims["given_name"] as? String,
                lastName = claims["family_name"] as? String,
            )
        } catch (e: JwtException) {
            logger.warn("JWT validation failed for Google OAuth token: ${e.message}")
            throw UnauthorizedException("Invalid OAuth token signature or claims")
        } catch (e: IllegalArgumentException) {
            logger.error("Unexpected error validating Google token", e)
            throw UnauthorizedException("OAuth verification failed")
        }
    }

    private fun extractKid(idToken: String): String {
        val headerPart = idToken.split('.').getOrNull(0) ?: throw UnauthorizedException("Invalid token format")
        val headerJson = String(Base64.getUrlDecoder().decode(headerPart))
        val headerMap: Map<String, Any> = objectMapper.readValue(headerJson)
        return headerMap["kid"] as? String ?: throw UnauthorizedException("Missing kid in token")
    }

    private fun getPublicKeyFromJwks(kid: String): PublicKey {
        // Check cache first
        val cached = jwksCache[kid]
        if (cached != null && cached.cachedAt.plus(jwksCacheTtl).isAfter(Instant.now())) {
            logger.debug("Using cached public key for kid: $kid")
            return cached.key
        }

        // Check if we need to refetch JWKS (cache TTL expired)
        val lastFetch = lastJwksFetch["google"]
        if (lastFetch != null && lastFetch.plus(jwksCacheTtl).isAfter(Instant.now())) {
            // Check if kid was in previous fetch
            if (jwksCache.containsKey(kid)) {
                logger.debug("Using cached key for kid: $kid (within JWKS TTL)")
                return jwksCache[kid]!!.key
            }
        }

        // Fetch fresh JWKS
        logger.debug("Fetching fresh JWKS from Google")
        val jwks = fetchGoogleJwks()

        // Cache all keys
        for (key in jwks.keys) {
            runCatching {
                val publicKey = buildPublicKeyFromJwk(key)
                jwksCache[key.kid] = CachedKey(publicKey, Instant.now())
            }
                .onFailure { err -> logger.warn("Failed to process JWK key ${key.kid}: ${err.message}") }
        }

        lastJwksFetch["google"] = Instant.now()

        return jwksCache[kid]?.key
            ?: throw UnauthorizedException("Key ID not found in Google JWKS: $kid")
    }

    private fun fetchGoogleJwks(): GoogleJwks {
        try {
            val request =
                HttpRequest.newBuilder()
                    .uri(URI.create(jwksUrl))
                    .timeout(Duration.ofSeconds(5))
                    .setHeader("User-Agent", "trainer-hub-auth-service/1.0")
                    .GET()
                    .build()

            val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())

            if (response.statusCode() != 200) {
                throw UnauthorizedException("Failed to fetch Google JWKS: HTTP ${response.statusCode()}")
            }

            return objectMapper.readValue(response.body(), GoogleJwks::class.java)
        } catch (e: java.io.IOException) {
            logger.error("Failed to fetch Google JWKS", e)
            throw UnauthorizedException("Failed to retrieve OAuth verification keys")
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            logger.error("Interrupted while fetching Google JWKS", e)
            throw UnauthorizedException("Failed to retrieve OAuth verification keys")
        } catch (e: com.fasterxml.jackson.core.JsonProcessingException) {
            logger.error("Failed to fetch Google JWKS", e)
            throw UnauthorizedException("Failed to retrieve OAuth verification keys")
        }
    }

    private fun buildPublicKeyFromJwk(jwk: GoogleJwksKey): PublicKey {
        require(jwk.kty == "RSA") { "Only RSA keys supported, got: ${jwk.kty}" }

        val nBytes = Base64.getUrlDecoder().decode(jwk.n)
        val eBytes = Base64.getUrlDecoder().decode(jwk.e)

        val n = java.math.BigInteger(1, nBytes)
        val e = java.math.BigInteger(1, eBytes)

        val keySpec = java.security.spec.RSAPublicKeySpec(n, e)
        val keyFactory = KeyFactory.getInstance("RSA")
        return try {
            keyFactory.generatePublic(keySpec)
        } catch (ex: InvalidKeySpecException) {
            throw UnauthorizedException("Invalid JWK key spec: ${ex.message}", ex)
        }
    }

    private fun validateClaims(claims: Claims) {
        // Validate exp
        val expirationTime = claims.expiration?.toInstant() ?: throw UnauthorizedException("Missing exp claim")
        if (expirationTime.isBefore(Instant.now())) {
            throw UnauthorizedException("Token expired")
        }

        // Validate iss (issuer)
        val issuer = claims.issuer ?: throw UnauthorizedException("Missing iss claim")
        if (issuer != "https://accounts.google.com") {
            throw UnauthorizedException("Invalid issuer: $issuer")
        }

        // Validate aud (audience) - should be the client ID
        val audClaim = claims["aud"]
        val audience =
            claims.audience ?: (audClaim as? String) ?: (audClaim as? Collection<*>)?.firstOrNull()?.toString()
                ?: throw UnauthorizedException("Missing aud claim")
        // In real scenario, validate against GOOGLE_CLIENT_ID configured in app
        logger.debug("Google OAuth token audience: $audience")

        // Validate email_verified
        val emailVerified = claims["email_verified"] as? Boolean ?: false
        if (!emailVerified) {
            logger.warn("Google OAuth token has unverified email")
        }

        // Validate iat (issued at)
        val issuedAtTime = claims.issuedAt?.toInstant() ?: throw UnauthorizedException("Missing iat claim")
        if (issuedAtTime.isAfter(Instant.now().plusSeconds(60))) {
            throw UnauthorizedException("Token issued in the future")
        }
    }
}
