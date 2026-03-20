package com.um.springbootprojstructure.auth;

import com.um.springbootprojstructure.security.HibpProperties;
import com.um.springbootprojstructure.security.PasswordResetProperties;
import com.um.springbootprojstructure.security.SecretWiper;
import com.um.springbootprojstructure.security.pwned.HibpPasswordChecker;
import com.um.springbootprojstructure.user.AccountStatus;
import com.um.springbootprojstructure.user.User;
import com.um.springbootprojstructure.user.UserRepository;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PasswordResetService {
    private static final SecureRandom RNG = new SecureRandom();

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordResetNotificationSender notificationSender;
    private final PasswordResetProperties properties;
    private final HibpPasswordChecker hibpPasswordChecker;
    private final HibpProperties hibpProperties;
    private final Clock clock;

    public PasswordResetService(
            UserRepository userRepository,
            PasswordResetTokenRepository tokenRepository,
            PasswordEncoder passwordEncoder,
            PasswordResetNotificationSender notificationSender,
            PasswordResetProperties properties,
            HibpPasswordChecker hibpPasswordChecker,
            HibpProperties hibpProperties,
            Clock clock
    ) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.notificationSender = notificationSender;
        this.properties = properties;
        this.hibpPasswordChecker = hibpPasswordChecker;
        this.hibpProperties = hibpProperties;
        this.clock = clock;
    }

    @Transactional
    public void requestReset(String identifier) {
        Instant now = Instant.now(clock);
        tokenRepository.deleteExpiredOrUsed(now);

        String normalized = normalizeIdentifier(identifier);
        Optional<User> userOpt = findByIdentifier(normalized);

        // SECURITY: [Layer 6] Always do comparable work to reduce account enumeration via timing.
        String token = generateToken();
        byte[] tokenHash = hashToken(token);

        if (userOpt.isEmpty()) {
            // do not persist token
            wipeBytes(tokenHash);
            return;
        }

        User user = userOpt.get();
        if (user.getStatus() != AccountStatus.ACTIVE) {
            wipeBytes(tokenHash);
            return;
        }

        // SECURITY: [Layer 6] Throttle reset requests per account.
        Optional<PasswordResetToken> last = tokenRepository.findTopByUserIdOrderByCreatedAtDesc(user.getId());
        if (last.isPresent() && last.get().getCreatedAt().plus(properties.minInterval()).isAfter(now)) {
            wipeBytes(tokenHash);
            return;
        }

        PasswordResetToken prt = new PasswordResetToken();
        prt.setUserId(user.getId());
        prt.setTokenHash(tokenHash);
        prt.setCreatedAt(now);
        prt.setExpiresAt(now.plus(properties.ttl()));
        prt.setUsedAt(null);
        tokenRepository.save(prt);

        // SECURITY: [Layer 6] Deliver reset token out-of-band; do not log or return it in API.
        notificationSender.sendResetToken(
                new PasswordResetNotificationSender.UserAccountSnapshot(user.getId(), user.getUsername(), user.getEmail()),
                token
        );
    }

    @Transactional
    public void confirmReset(String token, char[] newPassword) {
        try {
            Instant now = Instant.now(clock);
            tokenRepository.deleteExpiredOrUsed(now);

            if (token == null || token.isBlank()) {
                throw new InvalidResetTokenException();
            }

            byte[] tokenHash = hashToken(token);
            try {
                PasswordResetToken prt = tokenRepository.findByTokenHash(tokenHash).orElseThrow(InvalidResetTokenException::new);

                if (prt.getUsedAt() != null || now.isAfter(prt.getExpiresAt())) {
                    throw new InvalidResetTokenException();
                }

                User user = userRepository.findById(prt.getUserId()).orElseThrow(InvalidResetTokenException::new);
                if (user.getStatus() != AccountStatus.ACTIVE) {
                    throw new InvalidResetTokenException();
                }

                AuthService.validatePasswordPolicy(newPassword);
                if (hibpProperties.enabled() && hibpPasswordChecker.isBreached(newPassword)) {
                    throw new WeakPasswordException();
                }

                // SECURITY: [Layer 3] Rotate password hash; clear lockout counters on reset.
                String newHash = passwordEncoder.encode(CharBuffer.wrap(newPassword));
                user.setPasswordHash(newHash);
                user.setFailedLoginAttempts(0);
                user.setLockoutUntil(null);
                userRepository.save(user);

                prt.setUsedAt(now);
                tokenRepository.save(prt);

                // SECURITY: [Layer 6] Invalidate all reset tokens for this user after successful reset.
                tokenRepository.deleteAllForUser(user.getId());
            } finally {
                wipeBytes(tokenHash);
            }
        } finally {
            SecretWiper.wipe(newPassword);
        }
    }

    private Optional<User> findByIdentifier(String identifier) {
        boolean looksLikeEmail = identifier.contains("@");
        if (looksLikeEmail) {
            Optional<User> byEmail = userRepository.findByEmailIgnoreCase(identifier);
            return byEmail.isPresent() ? byEmail : userRepository.findByUsernameIgnoreCase(identifier);
        }
        Optional<User> byUsername = userRepository.findByUsernameIgnoreCase(identifier);
        return byUsername.isPresent() ? byUsername : userRepository.findByEmailIgnoreCase(identifier);
    }

    private static String normalizeIdentifier(String identifier) {
        if (identifier == null) {
            throw new IllegalArgumentException("identifier is required");
        }
        String trimmed = identifier.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("identifier is required");
        }
        // SECURITY: [Layer 6] Avoid lossy normalization; repository methods are case-insensitive.
        return trimmed;
    }

    private static String generateToken() {
        // SECURITY: [Layer 2] Use SecureRandom for reset tokens.
        byte[] bytes = new byte[32];
        RNG.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] hashToken(String token) {
        try {
            // SECURITY: [Layer 2] Hash token before persistence to prevent DB leakage from enabling resets.
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(token.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to hash reset token", e);
        }
    }

    private static void wipeBytes(byte[] bytes) {
        if (bytes == null) {
            return;
        }
        Arrays.fill(bytes, (byte) 0);
        java.lang.ref.Reference.reachabilityFence(bytes);
    }
}

