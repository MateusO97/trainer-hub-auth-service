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
@Table(name = "users")
class UserEntity(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false)
    var id: UUID? = null,
    @Column(name = "email", nullable = false, unique = true)
    var email: String,
    @Column(name = "password_hash")
    var passwordHash: String? = null,
    @Column(name = "first_name")
    var firstName: String? = null,
    @Column(name = "last_name")
    var lastName: String? = null,
    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    var role: UserRole = UserRole.USER,
    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true,
    @Column(name = "failed_login_attempts", nullable = false)
    var failedLoginAttempts: Int = 0,
    @Column(name = "locked_until")
    var lockedUntil: Instant? = null,
    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now(),
    @Column(name = "updated_at", nullable = false)
    var updatedAt: Instant = Instant.now(),
)
