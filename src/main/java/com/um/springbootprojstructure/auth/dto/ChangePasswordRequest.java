package com.um.springbootprojstructure.auth.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(
        // SECURITY: [Layer 5] Use char[] to minimize secret lifetime; wipe after use.
        @NotNull
        @Size(min = 1, max = 256)
        char[] currentPassword,

        // SECURITY: [Layer 5] Use char[] to minimize secret lifetime; wipe after use.
        @NotNull
        @Size(min = 12, max = 256)
        char[] newPassword
) {}

