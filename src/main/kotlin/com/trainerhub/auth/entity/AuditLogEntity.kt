package com.trainerhub.auth.entity

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "audit_log")
class AuditLogEntity(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false)
    var id: UUID? = null,
    @Column(name = "user_id")
    var userId: UUID? = null,
    @Enumerated(EnumType.STRING)
    @Column(name = "action", nullable = false)
    var action: AuditAction,
    @Column(name = "ip_address")
    var ipAddress: String? = null,
    @Column(name = "user_agent")
    var userAgent: String? = null,
    @Column(name = "details", columnDefinition = "TEXT")
    var details: String? = null,
    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now(),
)
