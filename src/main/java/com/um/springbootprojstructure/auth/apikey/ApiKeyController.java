package com.um.springbootprojstructure.auth.apikey;

import com.um.springbootprojstructure.auth.JwtSubject;
import com.um.springbootprojstructure.auth.apikey.dto.ApiKeySummaryResponse;
import com.um.springbootprojstructure.auth.apikey.dto.IssueApiKeyRequest;
import com.um.springbootprojstructure.auth.apikey.dto.IssueApiKeyResponse;
import com.um.springbootprojstructure.auth.apikey.dto.RevokeApiKeyResponse;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/auth/api-keys", produces = MediaType.APPLICATION_JSON_VALUE)
public class ApiKeyController {
    private final ApiKeyService apiKeyService;

    public ApiKeyController(ApiKeyService apiKeyService) {
        this.apiKeyService = apiKeyService;
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<IssueApiKeyResponse> issue(
            @AuthenticationPrincipal Jwt jwt,
            @Valid @RequestBody(required = false) IssueApiKeyRequest request
    ) {
        long userId = JwtSubject.requireUserId(jwt);
        String name = request == null ? null : request.name();
        ApiKeyService.IssuedApiKey issued = apiKeyService.issue(userId, name);
        return ResponseEntity.ok(new IssueApiKeyResponse(issued.id(), issued.prefix(), issued.apiKey(), "ACTIVE"));
    }

    @GetMapping
    public ResponseEntity<List<ApiKeySummaryResponse>> list(@AuthenticationPrincipal Jwt jwt) {
        long userId = JwtSubject.requireUserId(jwt);
        List<ApiKeySummaryResponse> out = apiKeyService.list(userId).stream()
                .map(k -> new ApiKeySummaryResponse(
                        k.getId(),
                        k.getPrefix(),
                        k.getName(),
                        k.getRevokedAt() == null ? "ACTIVE" : "REVOKED",
                        k.getCreatedAt(),
                        k.getRevokedAt()
                ))
                .toList();
        return ResponseEntity.ok(out);
    }

    @DeleteMapping("/{keyId}")
    public ResponseEntity<RevokeApiKeyResponse> revoke(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable long keyId
    ) {
        long userId = JwtSubject.requireUserId(jwt);
        apiKeyService.revoke(userId, keyId);
        return ResponseEntity.ok(new RevokeApiKeyResponse("REVOKED"));
    }
}

