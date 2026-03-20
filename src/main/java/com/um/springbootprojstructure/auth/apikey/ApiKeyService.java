package com.um.springbootprojstructure.auth.apikey;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ApiKeyService {
    private static final SecureRandom RNG = new SecureRandom();

    private final ApiKeyRepository apiKeyRepository;
    private final Clock clock;

    public ApiKeyService(ApiKeyRepository apiKeyRepository, Clock clock) {
        this.apiKeyRepository = apiKeyRepository;
        this.clock = clock;
    }

    @Transactional
    public IssuedApiKey issue(long ownerUserId, String name) {
        String apiKey = generateApiKey();
        byte[] hash = sha256(apiKey.getBytes(StandardCharsets.UTF_8));

        ApiKey entity = new ApiKey();
        entity.setOwnerUserId(ownerUserId);
        entity.setName(normalizeName(name));
        entity.setKeyHash(hash);
        entity.setPrefix(apiKey.substring(0, 8));
        entity.setCreatedAt(Instant.now(clock));
        entity.setRevokedAt(null);
        ApiKey saved = apiKeyRepository.save(entity);

        return new IssuedApiKey(saved.getId(), saved.getPrefix(), apiKey);
    }

    @Transactional(readOnly = true)
    public List<ApiKey> list(long ownerUserId) {
        return apiKeyRepository.findByOwnerUserIdOrderByCreatedAtDesc(ownerUserId);
    }

    @Transactional
    public void revoke(long ownerUserId, long keyId) {
        ApiKey key = apiKeyRepository.findByIdAndOwnerUserId(keyId, ownerUserId)
                .orElseThrow(ApiKeyNotFoundException::new);
        if (key.getRevokedAt() == null) {
            key.setRevokedAt(Instant.now(clock));
            apiKeyRepository.save(key);
        }
    }

    private static String normalizeName(String name) {
        if (name == null) {
            return null;
        }
        String trimmed = name.trim();
        return trimmed.isBlank() ? null : trimmed;
    }

    private static String generateApiKey() {
        // SECURITY: [Layer 2] SecureRandom-generated API key, URL-safe.
        byte[] bytes = new byte[32];
        RNG.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] sha256(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(bytes);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to hash API key", e);
        } finally {
            // SECURITY: [Layer 5] Best-effort wipe transient bytes.
            Arrays.fill(bytes, (byte) 0);
            java.lang.ref.Reference.reachabilityFence(bytes);
        }
    }

    public record IssuedApiKey(long id, String prefix, String apiKey) {}
}

