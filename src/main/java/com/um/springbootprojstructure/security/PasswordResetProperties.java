package com.um.springbootprojstructure.security;

import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "security.password-reset")
@Validated
public record PasswordResetProperties(
        @NotNull Duration ttl,
        @NotNull Duration minInterval
) {}

