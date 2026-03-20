package com.um.springbootprojstructure.auth.mfa.dto;

import java.time.Instant;

public record MfaVerifyResponse(String status, String tokenType, String token, Instant expiresAt) {}

