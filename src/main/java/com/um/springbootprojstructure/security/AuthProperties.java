package com.um.springbootprojstructure.security;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "security.auth")
@Validated
public record AuthProperties(
        @Min(1) @Max(50) int maxFailedAttempts,
        @NotNull Duration lockoutDuration
) {}

