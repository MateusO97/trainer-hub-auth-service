package com.trainerhub.auth.service

import com.trainerhub.auth.entity.AuditAction
import com.trainerhub.auth.entity.AuditLogEntity
import com.trainerhub.auth.repository.AuditLogRepository
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID
import org.springframework.scheduling.annotation.Async
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class AuditLogService(
    private val auditLogRepository: AuditLogRepository,
) {
    @Async
    fun log(
        action: AuditAction,
        userId: UUID? = null,
        ipAddress: String? = null,
        userAgent: String? = null,
        details: String? = null,
    ) {
        auditLogRepository.save(
            AuditLogEntity(
                userId = userId,
                action = action,
                ipAddress = ipAddress,
                userAgent = userAgent,
                details = details,
            ),
        )
    }

    @Transactional
    @Scheduled(cron = "0 0 2 * * *")
    fun cleanupOldLogs() {
        val cutoff = Instant.now().minus(90, ChronoUnit.DAYS)
        auditLogRepository.deleteOlderThan(cutoff)
    }
}
