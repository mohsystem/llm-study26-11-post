package com.um.springbootprojstructure.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(
        name = "app_users",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_app_users_email", columnNames = "email"),
                @UniqueConstraint(name = "uk_app_users_username", columnNames = "username"),
                @UniqueConstraint(name = "uk_app_users_public_ref", columnNames = "public_ref")
        }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // SECURITY: [Layer 6] Stable, non-guessable public reference (do not expose DB ids in URLs).
    @Column(name = "public_ref", nullable = false, length = 64)
    private String publicRef;

    @Column(nullable = false, length = 64)
    private String username;

    @Column(nullable = false, length = 320)
    private String email;

    @Column(length = 20)
    private String phoneNumber;

    /**
     * Store a hashed password (never plaintext). Hashing will be added once auth requirements are defined.
     */
    @Column(nullable = false, length = 255)
    private String passwordHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private UserRole role;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private AccountStatus status;

    @Column(nullable = false)
    private int failedLoginAttempts;

    @Column
    private Instant lockoutUntil;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant updatedAt;

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        this.createdAt = now;
        this.updatedAt = now;
        if (this.publicRef == null) {
            this.publicRef = generatePublicRef();
        }
        if (this.role == null) {
            this.role = UserRole.USER;
        }
        if (this.status == null) {
            this.status = AccountStatus.ACTIVE;
        }
    }

    @PreUpdate
    void onUpdate() {
        this.updatedAt = Instant.now();
    }

    private static String generatePublicRef() {
        // SECURITY: [Layer 2] Use SecureRandom for externally visible identifiers.
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}

