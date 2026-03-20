package com.um.springbootprojstructure.security;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "security.mfa")
@Validated
public record MfaProperties(
        @NotNull Duration ttl,
        @NotNull Duration minInterval,
        @Min(3) @Max(10) int maxAttempts
) {}

