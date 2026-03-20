package com.um.springbootprojstructure.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record ResetConfirmRequest(
        @NotBlank
        @Size(min = 20, max = 200)
        @Pattern(regexp = "^[A-Za-z0-9_-]{20,200}$")
        String token,

        // SECURITY: [Layer 5] Use char[] to minimize secret lifetime; wipe after use.
        @NotNull
        @Size(min = 12, max = 256)
        char[] newPassword
) {}

