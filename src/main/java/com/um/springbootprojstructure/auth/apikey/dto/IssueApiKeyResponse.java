package com.um.springbootprojstructure.auth.apikey.dto;

public record IssueApiKeyResponse(long id, String prefix, String apiKey, String status) {}

