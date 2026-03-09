package com.trainerhub.auth.repository

import com.trainerhub.auth.entity.OAuthProvider
import com.trainerhub.auth.entity.OAuthTokenEntity
import java.util.UUID
import org.springframework.data.jpa.repository.JpaRepository

interface OAuthTokenRepository : JpaRepository<OAuthTokenEntity, UUID> {
    fun findByProviderAndProviderUserId(
        provider: OAuthProvider,
        providerUserId: String,
    ): OAuthTokenEntity?
}
