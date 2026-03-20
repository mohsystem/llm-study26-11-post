package com.um.springbootprojstructure.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResetRequest(
        @NotBlank
        @Size(max = 320)
        String identifier
) {}

