package com.trainerhub.auth.repository

import com.trainerhub.auth.entity.RefreshTokenEntity
import com.trainerhub.auth.entity.UserEntity
import java.time.Instant
import java.util.UUID
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param

interface RefreshTokenRepository : JpaRepository<RefreshTokenEntity, UUID> {
    fun findByToken(token: String): RefreshTokenEntity?

    @Modifying
    @Query("update RefreshTokenEntity t set t.revokedAt = :now where t.user = :user and t.revokedAt is null")
    fun revokeAllForUser(
        @Param("user") user: UserEntity,
        @Param("now") now: Instant,
    ): Int

    @Modifying
    @Query("delete from RefreshTokenEntity t where t.expiresAt < :now")
    fun deleteExpired(
        @Param("now") now: Instant,
    ): Int
}
