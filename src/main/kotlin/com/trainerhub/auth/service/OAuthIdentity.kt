package com.trainerhub.auth.service

data class OAuthIdentity(
    val providerUserId: String,
    val email: String,
    val firstName: String? = null,
    val lastName: String? = null,
)
