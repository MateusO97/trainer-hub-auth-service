package com.trainerhub.auth.exception

class UnauthorizedException(message: String) : RuntimeException(message)

class BadRequestException(message: String) : RuntimeException(message)

class ForbiddenException(message: String) : RuntimeException(message)

class LockedException(message: String) : RuntimeException(message)
