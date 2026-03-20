package com.um.springbootprojstructure.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank
        @Size(min = 3, max = 64)
        @Pattern(regexp = "^[A-Za-z0-9_]{3,64}$")
        String username,

        @NotBlank
        @Email
        @Size(max = 320)
        String email,

        // SECURITY: [Layer 5] Use char[] to minimize secret lifetime; wipe after use.
        @NotNull
        @Size(min = 12, max = 256)
        char[] password
) {}

