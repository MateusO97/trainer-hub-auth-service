package com.trainerhub.auth.config

import com.trainerhub.auth.entity.OAuthProvider
import com.trainerhub.auth.service.AppleOAuthTokenVerifier
import com.trainerhub.auth.service.GoogleOAuthTokenVerifier
import com.trainerhub.auth.service.OAuthTokenVerifier
import org.springframework.stereotype.Component

/**
 * Factory para selecionar o verificador OAuth apropriado baseado no provider
 * Implementa strategy pattern para permitir diferentes validadores por provider
 */
@Component
class OAuthVerifierFactory(
    private val googleVerifier: GoogleOAuthTokenVerifier,
    private val appleVerifier: AppleOAuthTokenVerifier,
) {
    fun getVerifier(provider: OAuthProvider): OAuthTokenVerifier =
        when (provider) {
            OAuthProvider.GOOGLE -> googleVerifier
            OAuthProvider.APPLE -> appleVerifier
        }
}
