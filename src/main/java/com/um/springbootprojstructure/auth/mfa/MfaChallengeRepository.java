package com.um.springbootprojstructure.auth.mfa;

import java.time.Instant;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface MfaChallengeRepository extends JpaRepository<MfaChallenge, Long> {
    Optional<MfaChallenge> findByTokenHash(byte[] tokenHash);

    Optional<MfaChallenge> findTopByUserIdOrderByCreatedAtDesc(Long userId);

    Optional<MfaChallenge> findTopByUserIdAndVerifiedAtIsNullOrderByCreatedAtDesc(Long userId);

    @Modifying
    @Query("delete from MfaChallenge c where c.userId = :userId and c.verifiedAt is null")
    int deleteActiveForUser(@Param("userId") Long userId);

    @Modifying
    @Query("delete from MfaChallenge c where c.expiresAt < :now or c.verifiedAt is not null")
    int deleteExpiredOrVerified(@Param("now") Instant now);
}

