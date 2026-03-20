package com.um.springbootprojstructure.api;

import com.um.springbootprojstructure.auth.AccountDisabledException;
import com.um.springbootprojstructure.auth.AccountLockedException;
import com.um.springbootprojstructure.auth.AuthenticationFailedException;
import com.um.springbootprojstructure.auth.InvalidResetTokenException;
import com.um.springbootprojstructure.auth.WeakPasswordException;
import com.um.springbootprojstructure.auth.mfa.InvalidMfaException;
import com.um.springbootprojstructure.auth.apikey.ApiKeyNotFoundException;
import com.um.springbootprojstructure.admin.directory.DirectoryDisabledException;
import com.um.springbootprojstructure.user.DocumentNotFoundException;
import com.um.springbootprojstructure.user.DocumentTooLargeException;
import com.um.springbootprojstructure.user.UnsupportedDocumentTypeException;
import com.um.springbootprojstructure.user.UserAlreadyExistsException;
import com.um.springbootprojstructure.user.UserNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import java.util.List;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ProblemDetail handleValidation(MethodArgumentNotValidException ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        pd.setTitle("Invalid request");
        // SECURITY: [Layer 6] Do not echo rejected values; only field names.
        List<String> fields = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(FieldError::getField)
                .distinct()
                .toList();
        pd.setProperty("fields", fields);
        attachCorrelationId(pd, request);
        return pd;
    }

    @ExceptionHandler(ConstraintViolationException.class)
    ProblemDetail handleConstraintViolation(ConstraintViolationException ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        pd.setTitle("Invalid request");
        attachCorrelationId(pd, request);
        return pd;
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    ProblemDetail handleUserExists(UserAlreadyExistsException ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.CONFLICT);
        pd.setTitle("User already exists");
        attachCorrelationId(pd, request);
        return pd;
    }

    @ExceptionHandler(WeakPasswordException.class)
    ProblemDetail handleWeakPassword(WeakPasswordException ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        pd.setTitle("Weak password");
        attachCorrelationId(pd, request);
        return pd;
    }

    @ExceptionHandler(InvalidResetTokenException.class)
    ProblemDetail handleInvalidResetToken(InvalidResetTokenException ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        pd.setTitle("Invalid reset token");
        attachCorrelationId(pd, request);
        return pd;
    }

    @ExceptionHandler(InvalidMfaException.class)
    ProblemDetail handleInvalidMfa(InvalidMfaException ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        pd.setTitle("Invalid MFA code");
        attachCorrelationId(pd, request);
        return pd;
    }

    @ExceptionHandler(ApiKeyNotFoundException.class)
    ProblemDetail handleApiKeyNotFound(ApiKeyNotFoundException ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.NOT_FOUND);
        pd.setTitle("Not found");
        attachCorrelationId(pd, request);
        return pd;
    }

    @ExceptionHandler(DirectoryDisabledException.class)
    ProblemDetail handleDirectoryDisabled(DirectoryDisabledException ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.SERVICE_UNAVAILABLE);
        pd.setTitle("Directory service unavailable");
        attachCorrelationId(pd, request);
        return pd;
    }

    @ExceptionHandler(UserNotFoundException.class)
    ProblemDetail handleUserNotFound(UserNotFoundException ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.NOT_FOUND);
        pd.setTitle("Not found");
        attachCorrelationId(pd, request);
        return pd;
    }

    @ExceptionHandler(DocumentNotFoundException.class)
    ProblemDetail handleDocNotFound(DocumentNotFoundException ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.NOT_FOUND);
        pd.setTitle("Not found");
        attachCorrelationId(pd, request);
        return pd;
    }

    @ExceptionHandler({DocumentTooLargeException.class, MaxUploadSizeExceededException.class})
    ProblemDetail handleTooLarge(RuntimeException ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.PAYLOAD_TOO_LARGE);
        pd.setTitle("Payload too large");
        attachCorrelationId(pd, request);
        return pd;
    }

    @ExceptionHandler(UnsupportedDocumentTypeException.class)
    ProblemDetail handleUnsupportedType(UnsupportedDocumentTypeException ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
        pd.setTitle("Unsupported media type");
        attachCorrelationId(pd, request);
        return pd;
    }

    @ExceptionHandler(AuthenticationFailedException.class)
    ProblemDetail handleAuthFailed(AuthenticationFailedException ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.UNAUTHORIZED);
        pd.setTitle("Authentication failed");
        attachCorrelationId(pd, request);
        return pd;
    }

    @ExceptionHandler(AccountDisabledException.class)
    ProblemDetail handleAccountDisabled(AccountDisabledException ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.FORBIDDEN);
        pd.setTitle("Account disabled");
        attachCorrelationId(pd, request);
        return pd;
    }

    @ExceptionHandler(AccountLockedException.class)
    ProblemDetail handleAccountLocked(AccountLockedException ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.LOCKED);
        pd.setTitle("Account locked");
        pd.setProperty("lockedUntil", ex.getLockedUntil());
        attachCorrelationId(pd, request);
        return pd;
    }

    @ExceptionHandler({AccessDeniedException.class, AuthorizationDeniedException.class})
    ProblemDetail handleAccessDenied(RuntimeException ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.FORBIDDEN);
        pd.setTitle("Forbidden");
        attachCorrelationId(pd, request);
        return pd;
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ProblemDetail handleIllegalArgument(IllegalArgumentException ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        pd.setTitle("Invalid request");
        attachCorrelationId(pd, request);
        return pd;
    }

    @ExceptionHandler(Exception.class)
    ProblemDetail handleGeneric(Exception ex, HttpServletRequest request) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.INTERNAL_SERVER_ERROR);
        pd.setTitle("Internal server error");
        attachCorrelationId(pd, request);
        return pd;
    }

    private static void attachCorrelationId(ProblemDetail pd, HttpServletRequest request) {
        if (request == null) {
            return;
        }
        Object attr = request.getAttribute(CorrelationIdFilter.ATTRIBUTE_NAME);
        String cid = (attr instanceof String s) ? s : request.getHeader("X-Correlation-Id");
        if (cid != null && !cid.isBlank()) {
            // SECURITY: [Layer 6] Treat headers as untrusted; bound the size and strip CR/LF.
            String safe = cid.replaceAll("[\\r\\n]", "_");
            if (safe.length() > 128) {
                safe = safe.substring(0, 128);
            }
            pd.setProperty("correlationId", safe);
        }
    }
}

