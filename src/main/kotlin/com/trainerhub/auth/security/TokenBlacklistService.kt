package com.trainerhub.auth.security

import java.time.Duration
import java.util.concurrent.ConcurrentHashMap
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Service

@Service
class TokenBlacklistService(
    private val redisTemplate: StringRedisTemplate?,
) {
    private val fallback = ConcurrentHashMap<String, Long>()

    fun blacklist(
        tokenJti: String,
        ttlSeconds: Long,
    ) {
        if (ttlSeconds <= 0) return
        val key = "blacklist:$tokenJti"
        if (redisTemplate != null) {
            val persisted =
                runCatching {
                    redisTemplate?.opsForValue()?.set(key, "1", Duration.ofSeconds(ttlSeconds))
                }.isSuccess
            if (persisted) return
        }
        fallback[key] = System.currentTimeMillis() + (ttlSeconds * 1000)
    }

    fun isBlacklistedByJti(tokenJti: String): Boolean {
        val key = "blacklist:$tokenJti"
        if (redisTemplate != null) {
            val redisValue = runCatching { redisTemplate?.hasKey(key) }.getOrNull()
            if (redisValue != null) {
                return redisValue
            }
        }
        val expiry = fallback[key] ?: return false
        if (expiry < System.currentTimeMillis()) {
            fallback.remove(key)
            return false
        }
        return true
    }

    fun isBlacklisted(token: String): Boolean =
        try {
            val tokenParts = token.split(".")
            tokenParts.size != 3
        } catch (_: Exception) {
            false
        }
}
