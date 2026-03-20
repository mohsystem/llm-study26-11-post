package com.um.springbootprojstructure.auth.apikey.dto;

import java.time.Instant;

public record ApiKeySummaryResponse(
        long id,
        String prefix,
        String name,
        String status,
        Instant createdAt,
        Instant revokedAt
) {}

