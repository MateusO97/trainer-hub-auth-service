package com.trainerhub.auth.service

import java.time.Duration
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import org.springframework.stereotype.Service

@Service
class LoginAttemptService {
    private data class AttemptWindow(var attempts: Int, var expiresAt: Instant)

    private val attemptsByIp = ConcurrentHashMap<String, AttemptWindow>()
    private val maxAttempts = 5
    private val window = Duration.ofMinutes(15)

    fun onFailedAttempt(ipAddress: String) {
        val now = Instant.now()
        val current = attemptsByIp[ipAddress]
        if (current == null || current.expiresAt.isBefore(now)) {
            attemptsByIp[ipAddress] = AttemptWindow(1, now.plus(window))
            return
        }
        current.attempts += 1
    }

    fun clear(ipAddress: String) {
        attemptsByIp.remove(ipAddress)
    }

    fun isBlocked(ipAddress: String): Boolean {
        val current = attemptsByIp[ipAddress] ?: return false
        if (current.expiresAt.isBefore(Instant.now())) {
            attemptsByIp.remove(ipAddress)
            return false
        }
        return current.attempts >= maxAttempts
    }
}
