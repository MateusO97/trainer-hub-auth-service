package com.trainerhub.auth.repository

import com.trainerhub.auth.entity.PasswordResetTokenEntity
import java.time.Instant
import java.util.UUID
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param

interface PasswordResetTokenRepository : JpaRepository<PasswordResetTokenEntity, UUID> {
    fun findByToken(token: String): PasswordResetTokenEntity?

    @Modifying
    @Query("delete from PasswordResetTokenEntity t where t.expiresAt < :now")
    fun deleteExpired(
        @Param("now") now: Instant,
    ): Int
}
