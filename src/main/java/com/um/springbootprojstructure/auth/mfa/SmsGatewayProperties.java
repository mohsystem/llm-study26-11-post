package com.um.springbootprojstructure.auth.mfa;

import jakarta.validation.constraints.NotBlank;
import java.net.URI;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "security.mfa.sms")
@Validated
public record SmsGatewayProperties(
        boolean enabled,
        URI baseUrl,
        @NotBlank String sendPath,
        Duration connectTimeout,
        Duration requestTimeout
) {}

