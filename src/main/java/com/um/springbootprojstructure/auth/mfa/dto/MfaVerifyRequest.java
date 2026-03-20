package com.um.springbootprojstructure.auth.mfa.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record MfaVerifyRequest(
        @NotBlank
        @Size(max = 320)
        String identifier,

        // SECURITY: [Layer 5] OTP is short-lived/low-entropy. String enables Bean Validation; do not log it.
        @NotNull
        @Size(min = 6, max = 6)
        @Pattern(regexp = "^[0-9]{6}$")
        String code
) {}

