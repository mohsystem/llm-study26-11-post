package com.um.springbootprojstructure.auth;

import com.um.springbootprojstructure.auth.dto.ChangePasswordRequest;
import com.um.springbootprojstructure.auth.dto.LoginRequest;
import com.um.springbootprojstructure.auth.dto.LoginResponse;
import com.um.springbootprojstructure.auth.dto.RegisterRequest;
import com.um.springbootprojstructure.auth.dto.RegisterResponse;
import com.um.springbootprojstructure.auth.dto.ResetConfirmRequest;
import com.um.springbootprojstructure.auth.dto.ResetRequest;
import com.um.springbootprojstructure.auth.dto.StatusResponse;
import com.um.springbootprojstructure.user.User;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/auth", produces = MediaType.APPLICATION_JSON_VALUE)
public class AuthController {
    private final AuthService authService;
    private final PasswordResetService passwordResetService;

    public AuthController(AuthService authService, PasswordResetService passwordResetService) {
        this.authService = authService;
        this.passwordResetService = passwordResetService;
    }

    @PostMapping(path = "/register", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        User user = authService.register(request.username(), request.email(), request.password());
        RegisterResponse response = new RegisterResponse(user.getId(), "CREATED");
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping(path = "/login", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthService.AuthToken token = authService.login(request.identifier(), request.password());
        LoginResponse response = new LoginResponse("Bearer", token.token(), token.expiresAt());
        return ResponseEntity.ok(response);
    }

    @PostMapping(path = "/change-password", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<StatusResponse> changePassword(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody ChangePasswordRequest request
    ) {
        // SECURITY: [Layer 6] Derive user identity from server-validated JWT, not from request body.
        long userId = JwtSubject.requireUserId(jwt);
        authService.changePassword(userId, request.currentPassword(), request.newPassword());
        return ResponseEntity.ok(new StatusResponse("PASSWORD_CHANGED"));
    }

    @PostMapping(path = "/reset-request", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<StatusResponse> resetRequest(@Valid @RequestBody ResetRequest request) {
        // SECURITY: [Layer 6] Enumeration-safe: always return 200 with the same response shape.
        passwordResetService.requestReset(request.identifier());
        return ResponseEntity.ok(new StatusResponse("RESET_REQUESTED"));
    }

    @PostMapping(path = "/reset-confirm", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<StatusResponse> resetConfirm(@Valid @RequestBody ResetConfirmRequest request) {
        passwordResetService.confirmReset(request.token(), request.newPassword());
        return ResponseEntity.ok(new StatusResponse("RESET_CONFIRMED"));
    }
}

