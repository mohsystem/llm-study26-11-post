package com.um.springbootprojstructure.auth.apikey.dto;

import jakarta.validation.constraints.Size;

public record IssueApiKeyRequest(
        @Size(max = 100) String name
) {}

