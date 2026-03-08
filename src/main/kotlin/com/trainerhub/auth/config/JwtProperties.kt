package com.trainerhub.auth.config

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "jwt")
data class JwtProperties(
    var expiration: Long = 3600,
    var refreshExpiration: Long = 604800,
    var issuer: String = "trainer-hub-auth-service",
)
