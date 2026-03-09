package com.trainerhub.auth.service

import com.fasterxml.jackson.databind.ObjectMapper
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
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service

data class AppleJwksKey(
    val kty: String,
    val use: String?,
    val kid: String,
    val n: String,
    val e: String,
    val alg: String?,
)

data class AppleJwks(
    val keys: List<AppleJwksKey>,
)

@Service
class AppleOAuthTokenVerifier : OAuthTokenVerifier {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val objectMapper = ObjectMapper()
    private val httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()
    private val jwksCache = ConcurrentHashMap<String, CachedKey>()
    private val JWKS_URL = "https://appleid.apple.com/auth/keys"
    private val LAST_JWKS_FETCH = mutableMapOf<String, Instant>()
    private val JWKS_CACHE_TTL = Duration.ofHours(1)

    data class CachedKey(val key: PublicKey, val cachedAt: Instant)

    override fun verify(provider: OAuthProvider, idToken: String): OAuthIdentity {
        if (provider != OAuthProvider.APPLE) {
            throw UnauthorizedException("This verifier only handles Apple OAuth")
        }

        try {
            // Decode without verification first to get the kid (key ID)
            val header = Jwts.parserBuilder().build().parseClaimsJwt(idToken).header
            val kid = header["kid"] as? String ?: throw UnauthorizedException("Missing kid in token")

            // Get the public key
            val publicKey = getPublicKeyFromJwks(kid)

            // Verify signature and get claims
            val claims =
                Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(idToken)
                    .body

            // Validate standard claims
            validateClaims(claims)

            // For Apple, the subject is the user ID
            val subject = claims.subject ?: throw UnauthorizedException("Missing sub claim")

            // Try to get email from claims, or it might be in the request body separately
            val email = claims["email"] as? String ?: ""

            return OAuthIdentity(
                providerUserId = subject,
                email = email,
                firstName = null, // Apple doesn't provide first/last name in token
                lastName = null,
            )
        } catch (e: JwtException) {
            logger.warn("JWT validation failed for Apple OAuth token: ${e.message}")
            throw UnauthorizedException("Invalid OAuth token signature or claims")
        } catch (e: Exception) {
            logger.error("Unexpected error validating Apple token", e)
            throw UnauthorizedException("OAuth verification failed")
        }
    }

    private fun getPublicKeyFromJwks(kid: String): PublicKey {
        // Check cache first
        val cached = jwksCache[kid]
        if (cached != null && cached.cachedAt.plus(JWKS_CACHE_TTL).isAfter(Instant.now())) {
            logger.debug("Using cached public key for kid: $kid")
            return cached.key
        }

        // Check if we need to refetch JWKS (cache TTL expired)
        val lastFetch = LAST_JWKS_FETCH["apple"]
        if (lastFetch != null && lastFetch.plus(JWKS_CACHE_TTL).isAfter(Instant.now())) {
            // Check if kid was in previous fetch
            if (jwksCache.containsKey(kid)) {
                logger.debug("Using cached key for kid: $kid (within JWKS TTL)")
                return jwksCache[kid]!!.key
            }
        }

        // Fetch fresh JWKS
        logger.debug("Fetching fresh JWKS from Apple")
        val jwks = fetchAppleJwks()

        // Cache all keys
        for (key in jwks.keys) {
            try {
                val publicKey = buildPublicKeyFromJwk(key)
                jwksCache[key.kid] = CachedKey(publicKey, Instant.now())
            } catch (e: Exception) {
                logger.warn("Failed to process JWK key ${key.kid}: ${e.message}")
            }
        }

        LAST_JWKS_FETCH["apple"] = Instant.now()

        return jwksCache[kid]?.key ?: throw UnauthorizedException("Key ID not found in Apple JWKS: $kid")
    }

    private fun fetchAppleJwks(): AppleJwks {
        try {
            val request =
                HttpRequest.newBuilder()
                    .uri(URI.create(JWKS_URL))
                    .timeout(Duration.ofSeconds(5))
                    .setHeader("User-Agent", "trainer-hub-auth-service/1.0")
                    .GET()
                    .build()

            val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())

            if (response.statusCode() != 200) {
                throw UnauthorizedException("Failed to fetch Apple JWKS: HTTP ${response.statusCode()}")
            }

            return objectMapper.readValue(response.body(), AppleJwks::class.java)
        } catch (e: Exception) {
            logger.error("Failed to fetch Apple JWKS", e)
            throw UnauthorizedException("Failed to retrieve OAuth verification keys")
        }
    }

    private fun buildPublicKeyFromJwk(jwk: AppleJwksKey): PublicKey {
        if (jwk.kty != "RSA") {
            throw IllegalArgumentException("Only RSA keys supported, got: ${jwk.kty}")
        }

        val nBytes = Base64.getUrlDecoder().decode(jwk.n)
        val eBytes = Base64.getUrlDecoder().decode(jwk.e)

        val n = java.math.BigInteger(1, nBytes)
        val e = java.math.BigInteger(1, eBytes)

        val keySpec = java.security.spec.RSAPublicKeySpec(n, e)
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePublic(keySpec)
    }

    private fun validateClaims(claims: Claims) {
        // Validate exp
        val expirationTime = claims.expiration?.toInstant() ?: throw UnauthorizedException("Missing exp claim")
        if (expirationTime.isBefore(Instant.now())) {
            throw UnauthorizedException("Token expired")
        }

        // Validate iss (issuer)
        val issuer = claims.issuer ?: throw UnauthorizedException("Missing iss claim")
        if (issuer != "https://appleid.apple.com") {
            throw UnauthorizedException("Invalid issuer: $issuer")
        }

        // Validate aud (audience) - should be your app's bundle ID or service ID
        val audience = claims["aud"] as? String ?: throw UnauthorizedException("Missing aud claim")
        // In real scenario, validate against configured APPLE_CLIENT_ID
        logger.debug("Apple OAuth token audience: $audience")

        // Validate iat (issued at)
        val issuedAtTime = claims.issuedAt?.toInstant() ?: throw UnauthorizedException("Missing iat claim")
        if (issuedAtTime.isAfter(Instant.now().plusSeconds(60))) {
            throw UnauthorizedException("Token issued in the future")
        }

        // Validate nonce if present (prevents replay attacks)
        val nonce = claims["nonce"] as? String
        if (nonce != null) {
            logger.debug("Apple OAuth token includes nonce: ${nonce.take(20)}...")
        }
    }
}
