package com.um.springbootprojstructure.auth.mfa;

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
        name = "mfa_challenges",
        uniqueConstraints = @UniqueConstraint(name = "uk_mfa_challenges_token_hash", columnNames = "token_hash"),
        indexes = {
                @Index(name = "idx_mfa_challenges_user", columnList = "user_id"),
                @Index(name = "idx_mfa_challenges_expires", columnList = "expires_at")
        }
)
@Getter
@Setter
@NoArgsConstructor
public class MfaChallenge {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    // SECURITY: [Layer 6] Store only hashed opaque mfaToken (never plaintext).
    @Column(name = "token_hash", nullable = false, length = 32)
    private byte[] tokenHash;

    // SECURITY: [Layer 6] Store only hashed OTP (salted).
    @Column(name = "otp_salt", nullable = false, length = 16)
    private byte[] otpSalt;

    @Column(name = "otp_hash", nullable = false, length = 32)
    private byte[] otpHash;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false, updatable = false)
    private Instant expiresAt;

    @Column(name = "attempts", nullable = false)
    private int attempts;

    @Column(name = "verified_at")
    private Instant verifiedAt;
}

