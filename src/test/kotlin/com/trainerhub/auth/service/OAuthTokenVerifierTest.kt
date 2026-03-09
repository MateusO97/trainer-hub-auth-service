package com.trainerhub.auth.service

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.trainerhub.auth.entity.OAuthProvider
import com.trainerhub.auth.exception.UnauthorizedException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.mockk.every
import io.mockk.mockk
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import java.util.Date
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class OAuthTokenVerifierTest {
    @Test
    fun `google verifier should validate token with mocked jwks`() {
        val keyPair = generateRsaKeyPair()
        val kid = "google-kid-1"
        val token =
            buildToken(
                keyPair = keyPair,
                kid = kid,
                issuer = "https://accounts.google.com",
                audience = "google-client-id",
                email = "test@gmail.com",
                givenName = "Test",
                familyName = "User",
                emailVerified = true,
            )

        val httpClient = mockHttpClientWithJwks(jwksJsonFor(kid, keyPair.public as RSAPublicKey))
        val verifier = GoogleOAuthTokenVerifier(httpClient = httpClient, objectMapper = jacksonObjectMapper())

        val identity = verifier.verify(OAuthProvider.GOOGLE, token)

        assertEquals("test@gmail.com", identity.email)
        assertEquals("Test", identity.firstName)
        assertEquals("User", identity.lastName)
    }

    @Test
    fun `google verifier should reject wrong provider`() {
        val verifier = GoogleOAuthTokenVerifier()

        assertThrows(UnauthorizedException::class.java) {
            verifier.verify(OAuthProvider.APPLE, "invalid")
        }
    }

    @Test
    fun `apple verifier should validate token with mocked jwks`() {
        val keyPair = generateRsaKeyPair()
        val kid = "apple-kid-1"
        val token =
            buildToken(
                keyPair = keyPair,
                kid = kid,
                issuer = "https://appleid.apple.com",
                audience = "apple-client-id",
                email = "test@icloud.com",
            )

        val httpClient = mockHttpClientWithJwks(jwksJsonFor(kid, keyPair.public as RSAPublicKey))
        val verifier = AppleOAuthTokenVerifier(httpClient = httpClient, objectMapper = jacksonObjectMapper())

        val identity = verifier.verify(OAuthProvider.APPLE, token)

        assertEquals("test@icloud.com", identity.email)
    }

    @Test
    fun `apple verifier should reject invalid issuer`() {
        val keyPair = generateRsaKeyPair()
        val kid = "apple-kid-2"
        val token =
            buildToken(
                keyPair = keyPair,
                kid = kid,
                issuer = "https://invalid-issuer.example",
                audience = "apple-client-id",
                email = "test@icloud.com",
            )

        val httpClient = mockHttpClientWithJwks(jwksJsonFor(kid, keyPair.public as RSAPublicKey))
        val verifier = AppleOAuthTokenVerifier(httpClient = httpClient, objectMapper = jacksonObjectMapper())

        assertThrows(UnauthorizedException::class.java) {
            verifier.verify(OAuthProvider.APPLE, token)
        }
    }

    private fun mockHttpClientWithJwks(jwksJson: String): HttpClient {
        val httpClient = mockk<HttpClient>()
        val response = mockk<HttpResponse<String>>()

        every { response.statusCode() } returns 200
        every { response.body() } returns jwksJson
        every {
            httpClient.send(any<HttpRequest>(), any<HttpResponse.BodyHandler<String>>())
        } returns response

        return httpClient
    }

    private fun generateRsaKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    private fun buildToken(
        keyPair: KeyPair,
        kid: String,
        issuer: String,
        audience: String,
        email: String,
        givenName: String? = null,
        familyName: String? = null,
        emailVerified: Boolean? = null,
    ): String {
        val now = Date()
        val exp = Date(now.time + 60_000)

        val builder =
            Jwts
                .builder()
                .setHeaderParam("kid", kid)
                .setSubject(UUID.randomUUID().toString())
                .setIssuer(issuer)
                .setIssuedAt(now)
                .setExpiration(exp)
                .claim("aud", audience)
                .claim("email", email)

        if (givenName != null) builder.claim("given_name", givenName)
        if (familyName != null) builder.claim("family_name", familyName)
        if (emailVerified != null) builder.claim("email_verified", emailVerified)

        return builder.signWith(keyPair.private, SignatureAlgorithm.RS256).compact()
    }

    private fun jwksJsonFor(
        kid: String,
        publicKey: RSAPublicKey,
    ): String {
        val n = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.modulus.toByteArray().trimSignByte())
        val e =
            Base64.getUrlEncoder().withoutPadding().encodeToString(
                publicKey.publicExponent.toByteArray().trimSignByte(),
            )
        return """
            {
              "keys": [
                {
                  "kty": "RSA",
                  "kid": "$kid",
                  "use": "sig",
                  "n": "$n",
                  "e": "$e"
                }
              ]
            }
            """.trimIndent()
    }

    private fun ByteArray.trimSignByte(): ByteArray =
        if (isNotEmpty() && this[0] == 0.toByte()) {
            copyOfRange(1, size)
        } else {
            this
        }
}
