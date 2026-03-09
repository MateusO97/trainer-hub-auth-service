package com.trainerhub.auth.service

import com.trainerhub.auth.entity.OAuthProvider

interface OAuthTokenVerifier {
    fun verify(
        provider: OAuthProvider,
        idToken: String,
    ): OAuthIdentity
}
