package com.um.springbootprojstructure.auth.mfa.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record MfaChallengeRequest(
        @NotBlank
        @Size(max = 320)
        String identifier,

        // SECURITY: [Layer 5] Use char[] to minimize secret lifetime; wipe after use.
        @NotNull
        @Size(min = 1, max = 256)
        char[] password
) {}

