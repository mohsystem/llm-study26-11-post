package com.um.springbootprojstructure.auth.mfa;

import com.um.springbootprojstructure.auth.AuthService;
import com.um.springbootprojstructure.security.MfaProperties;
import com.um.springbootprojstructure.security.SecretWiper;
import com.um.springbootprojstructure.user.AccountStatus;
import com.um.springbootprojstructure.user.User;
import com.um.springbootprojstructure.user.UserRepository;
import java.nio.charset.StandardCharsets;
import java.nio.CharBuffer;
import java.nio.ByteBuffer;
import java.nio.charset.CharsetEncoder;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class MfaService {
    private static final SecureRandom RNG = new SecureRandom();

    private final AuthService authService;
    private final MfaChallengeRepository challengeRepository;
    private final UserRepository userRepository;
    private final SmsGateway smsGateway;
    private final MfaProperties properties;
    private final Clock clock;

    public MfaService(
            AuthService authService,
            MfaChallengeRepository challengeRepository,
            UserRepository userRepository,
            SmsGateway smsGateway,
            MfaProperties properties,
            Clock clock
    ) {
        this.authService = authService;
        this.challengeRepository = challengeRepository;
        this.userRepository = userRepository;
        this.smsGateway = smsGateway;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional
    public void challenge(String identifier, char[] password) {
        try {
            Instant now = Instant.now(clock);
            challengeRepository.deleteExpiredOrVerified(now);

            // SECURITY: [Layer 6] Step 1 auth (password) must succeed before OTP issuance.
            User user = authService.authenticateByPassword(identifier, password);
            if (user.getPhoneNumber() == null || user.getPhoneNumber().isBlank()) {
                throw new AccessDeniedException("MFA not configured");
            }

            Optional<MfaChallenge> last = challengeRepository.findTopByUserIdOrderByCreatedAtDesc(user.getId());
            if (last.isPresent() && last.get().getCreatedAt().plus(properties.minInterval()).isAfter(now)) {
                // SECURITY: [Layer 6] Throttle challenge creation. Do not create a new challenge.
                return;
            }

            char[] otp = generateOtp();
            byte[] otpSalt = new byte[16];
            RNG.nextBytes(otpSalt);
            byte[] otpHash = hashOtp(otpSalt, otp);

            // SECURITY: [Layer 6] Keep a single active challenge per user.
            challengeRepository.deleteActiveForUser(user.getId());

            MfaChallenge c = new MfaChallenge();
            c.setUserId(user.getId());
            c.setTokenHash(sha256(randomBytes(32)));
            c.setOtpSalt(otpSalt);
            c.setOtpHash(otpHash);
            c.setCreatedAt(now);
            c.setExpiresAt(now.plus(properties.ttl()));
            c.setAttempts(0);
            c.setVerifiedAt(null);
            challengeRepository.save(c);

            // SECURITY: [Layer 6] Out-of-band delivery only (do not log OTP).
            String otpString = new String(otp);
            try {
                String message = "Your verification code is: " + otpString;
                smsGateway.sendOtp(user.getPhoneNumber(), message);
            } finally {
                // SECURITY: [Layer 5] Best-effort reduce secret lifetime (String cannot be wiped).
                SecretWiper.wipe(otp);
            }
        } finally {
            SecretWiper.wipe(password);
        }
    }

    @Transactional
    public AuthService.AuthToken verify(String identifier, char[] code) {
        try {
            Instant now = Instant.now(clock);
            challengeRepository.deleteExpiredOrVerified(now);

            String normalized = normalizeRequired(identifier, "identifier");
            User user = findByIdentifier(normalized).orElseThrow(InvalidMfaException::new);
            if (user.getStatus() != AccountStatus.ACTIVE) {
                throw new InvalidMfaException();
            }

            MfaChallenge c = challengeRepository
                    .findTopByUserIdAndVerifiedAtIsNullOrderByCreatedAtDesc(user.getId())
                    .orElseThrow(InvalidMfaException::new);

            if (now.isAfter(c.getExpiresAt())) {
                throw new InvalidMfaException();
            }
            if (c.getAttempts() >= properties.maxAttempts()) {
                throw new InvalidMfaException();
            }

            byte[] candidate = hashOtp(c.getOtpSalt(), code);
            boolean ok = MessageDigest.isEqual(candidate, c.getOtpHash());
            if (!ok) {
                c.setAttempts(Math.addExact(c.getAttempts(), 1));
                challengeRepository.save(c);
                throw new InvalidMfaException();
            }

            c.setVerifiedAt(now);
            challengeRepository.save(c);
            return authService.issueJwt(user);
        } finally {
            SecretWiper.wipe(code);
        }
    }

    private static char[] generateOtp() {
        int n = RNG.nextInt(1_000_000);
        String s = String.format("%06d", n);
        return s.toCharArray();
    }

    private static byte[] hashOtp(byte[] salt, char[] otp) {
        byte[] otpBytes = null;
        try {
            // SECURITY: [Layer 2] Salted SHA-256 hash for OTP storage (short-lived, single-use).
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            otpBytes = utf8(otp);
            md.update(otpBytes);
            return md.digest();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to hash OTP", e);
        } finally {
            if (otpBytes != null) {
                wipeBytes(otpBytes);
            }
        }
    }

    private static byte[] utf8(char[] chars) {
        try {
            // SECURITY: [Layer 1] Explicit UTF-8 encoding; avoid platform defaults.
            CharsetEncoder enc = StandardCharsets.UTF_8.newEncoder();
            ByteBuffer bb = enc.encode(CharBuffer.wrap(chars));
            byte[] out = new byte[bb.remaining()];
            bb.get(out);
            return out;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encode OTP", e);
        }
    }

    private static byte[] sha256(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(bytes);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to hash token", e);
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

    private static String normalizeRequired(String value, String field) {
        if (value == null) {
            throw new IllegalArgumentException(field + " is required");
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return trimmed;
    }

    private static byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        RNG.nextBytes(bytes);
        return bytes;
    }

    private static void wipeBytes(byte[] bytes) {
        if (bytes == null) {
            return;
        }
        Arrays.fill(bytes, (byte) 0);
        java.lang.ref.Reference.reachabilityFence(bytes);
    }
}

