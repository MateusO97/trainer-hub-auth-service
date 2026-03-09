package com.trainerhub.auth.repository

import com.trainerhub.auth.entity.UserEntity
import java.util.UUID
import org.springframework.data.jpa.repository.JpaRepository

interface UserRepository : JpaRepository<UserEntity, UUID> {
    fun findByEmail(email: String): UserEntity?
}
