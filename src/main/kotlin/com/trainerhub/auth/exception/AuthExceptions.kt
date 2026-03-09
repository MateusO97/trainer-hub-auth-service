package com.trainerhub.auth.exception

class UnauthorizedException(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

class BadRequestException(message: String) : RuntimeException(message)

class ForbiddenException(message: String) : RuntimeException(message)

class LockedException(message: String) : RuntimeException(message)
