package com.trainerhub.auth.service

import com.trainerhub.auth.entity.OAuthProvider
import com.trainerhub.auth.exception.UnauthorizedException
import org.springframework.stereotype.Service

@Service
class DefaultOAuthTokenVerifier : OAuthTokenVerifier {
    override fun verify(
        provider: OAuthProvider,
        idToken: String,
    ): OAuthIdentity {
        // Development-friendly verifier: expected format <providerUserId>|<email>|<firstName>|<lastName>
        // Real provider signature verification should be wired here in production.
        val parts = idToken.split("|")
        if (parts.size < 2) {
            throw UnauthorizedException("Invalid OAuth token")
        }
        return OAuthIdentity(
            providerUserId = "${provider.name.lowercase()}-${parts[0]}",
            email = parts[1],
            firstName = parts.getOrNull(2),
            lastName = parts.getOrNull(3),
        )
    }
}
