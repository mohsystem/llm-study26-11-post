package com.um.springbootprojstructure.security;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "security.identity-document")
@Validated
public record IdentityDocumentProperties(
        @Min(1) @Max(20_000_000) long maxBytes
) {}

