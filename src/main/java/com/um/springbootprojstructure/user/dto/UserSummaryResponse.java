package com.um.springbootprojstructure.user.dto;

import com.um.springbootprojstructure.user.AccountStatus;
import com.um.springbootprojstructure.user.UserRole;
import java.time.Instant;

public record UserSummaryResponse(
        long id,
        String username,
        String email,
        UserRole role,
        AccountStatus status,
        Instant createdAt
) {}

