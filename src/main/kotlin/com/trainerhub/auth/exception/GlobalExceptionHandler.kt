package com.trainerhub.auth.exception

import com.trainerhub.auth.dto.GenericMessageResponse
import jakarta.validation.ConstraintViolationException
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.validation.FieldError
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice

@RestControllerAdvice
class GlobalExceptionHandler {
    @ExceptionHandler(UnauthorizedException::class)
    fun handleUnauthorized(ex: UnauthorizedException): ResponseEntity<GenericMessageResponse> =
        ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(GenericMessageResponse(ex.message ?: "Unauthorized"))

    @ExceptionHandler(ForbiddenException::class)
    fun handleForbidden(ex: ForbiddenException): ResponseEntity<GenericMessageResponse> =
        ResponseEntity.status(HttpStatus.FORBIDDEN).body(GenericMessageResponse(ex.message ?: "Forbidden"))

    @ExceptionHandler(LockedException::class)
    fun handleLocked(ex: LockedException): ResponseEntity<GenericMessageResponse> =
        ResponseEntity.status(HttpStatus.LOCKED).body(GenericMessageResponse(ex.message ?: "Account locked"))

    @ExceptionHandler(BadRequestException::class)
    fun handleBadRequest(ex: BadRequestException): ResponseEntity<GenericMessageResponse> =
        ResponseEntity.badRequest().body(GenericMessageResponse(ex.message ?: "Bad request"))

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidation(ex: MethodArgumentNotValidException): ResponseEntity<GenericMessageResponse> {
        val firstFieldError = ex.bindingResult.allErrors.firstOrNull() as? FieldError
        val message = firstFieldError?.defaultMessage ?: "Validation error"
        return ResponseEntity.badRequest().body(GenericMessageResponse(message))
    }

    @ExceptionHandler(ConstraintViolationException::class)
    fun handleConstraint(ex: ConstraintViolationException): ResponseEntity<GenericMessageResponse> =
        ResponseEntity.badRequest().body(GenericMessageResponse(ex.message ?: "Constraint violation"))
}
