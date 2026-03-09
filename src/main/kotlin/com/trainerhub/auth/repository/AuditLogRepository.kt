package com.trainerhub.auth.repository

import com.trainerhub.auth.entity.AuditLogEntity
import java.time.Instant
import java.util.UUID
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param

interface AuditLogRepository : JpaRepository<AuditLogEntity, UUID> {
    @Modifying
    @Query("delete from AuditLogEntity a where a.createdAt < :cutoff")
    fun deleteOlderThan(
        @Param("cutoff") cutoff: Instant,
    ): Int
}
