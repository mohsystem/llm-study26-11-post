package com.um.springbootprojstructure.auth;

import java.time.Instant;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    Optional<PasswordResetToken> findByTokenHash(byte[] tokenHash);

    Optional<PasswordResetToken> findTopByUserIdOrderByCreatedAtDesc(Long userId);

    @Modifying
    @Query("delete from PasswordResetToken t where t.expiresAt < :now or t.usedAt is not null")
    int deleteExpiredOrUsed(@Param("now") Instant now);

    @Modifying
    @Query("delete from PasswordResetToken t where t.userId = :userId")
    int deleteAllForUser(@Param("userId") Long userId);
}

