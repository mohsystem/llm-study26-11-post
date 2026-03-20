package com.um.springbootprojstructure.auth.apikey;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(
        name = "api_keys",
        uniqueConstraints = @UniqueConstraint(name = "uk_api_keys_hash", columnNames = "key_hash"),
        indexes = {
                @Index(name = "idx_api_keys_owner", columnList = "owner_user_id"),
                @Index(name = "idx_api_keys_revoked", columnList = "revoked_at")
        }
)
@Getter
@Setter
@NoArgsConstructor
public class ApiKey {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "owner_user_id", nullable = false)
    private Long ownerUserId;

    @Column(name = "name", length = 100)
    private String name;

    // SECURITY: [Layer 6] Store only a hash of the API key (never plaintext).
    @Column(name = "key_hash", nullable = false, length = 32)
    private byte[] keyHash;

    // SECURITY: [Layer 6] Non-secret prefix to help identify keys in UI/logs without revealing full key.
    @Column(name = "prefix", nullable = false, length = 16)
    private String prefix;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;
}

