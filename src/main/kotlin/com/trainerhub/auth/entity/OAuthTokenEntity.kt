package com.trainerhub.auth.entity

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.FetchType
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.JoinColumn
import jakarta.persistence.ManyToOne
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "oauth_tokens")
class OAuthTokenEntity(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false)
    var id: UUID? = null,
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    var user: UserEntity,
    @Enumerated(EnumType.STRING)
    @Column(name = "provider", nullable = false)
    var provider: OAuthProvider,
    @Column(name = "provider_user_id", nullable = false)
    var providerUserId: String,
    @Column(name = "access_token")
    var accessToken: String? = null,
    @Column(name = "refresh_token")
    var refreshToken: String? = null,
    @Column(name = "expires_at")
    var expiresAt: Instant? = null,
    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now(),
    @Column(name = "updated_at", nullable = false)
    var updatedAt: Instant = Instant.now(),
)
