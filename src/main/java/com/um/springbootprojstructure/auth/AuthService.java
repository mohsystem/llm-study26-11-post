package com.um.springbootprojstructure.auth;

import com.um.springbootprojstructure.security.AuthProperties;
import com.um.springbootprojstructure.security.HibpProperties;
import com.um.springbootprojstructure.security.JwtProperties;
import com.um.springbootprojstructure.security.SecretWiper;
import com.um.springbootprojstructure.security.pwned.HibpPasswordChecker;
import com.um.springbootprojstructure.user.AccountStatus;
import com.um.springbootprojstructure.user.User;
import com.um.springbootprojstructure.user.UserAlreadyExistsException;
import com.um.springbootprojstructure.user.UserRepository;
import com.um.springbootprojstructure.user.UserRole;
import java.nio.CharBuffer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtEncoder jwtEncoder;
    private final JwtProperties jwtProperties;
    private final AuthProperties authProperties;
    private final HibpPasswordChecker hibpPasswordChecker;
    private final HibpProperties hibpProperties;
    private final Clock clock;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtEncoder jwtEncoder,
            JwtProperties jwtProperties,
            AuthProperties authProperties,
            HibpPasswordChecker hibpPasswordChecker,
            HibpProperties hibpProperties,
            Clock clock
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtEncoder = jwtEncoder;
        this.jwtProperties = jwtProperties;
        this.authProperties = authProperties;
        this.hibpPasswordChecker = hibpPasswordChecker;
        this.hibpProperties = hibpProperties;
        this.clock = clock;
    }

    @Transactional
    public User register(String username, String email, char[] password) {
        try {
            String normalizedUsername = normalizeUsername(username);
            String normalizedEmail = normalizeEmail(email);

            validatePasswordPolicy(password);

            if (hibpProperties.enabled()) {
                // SECURITY: [Layer 6] Optional breached password check via k-anonymity.
                if (hibpPasswordChecker.isBreached(password)) {
                    throw new WeakPasswordException();
                }
            }

            if (userRepository.existsByUsernameIgnoreCase(normalizedUsername)) {
                // SECURITY: [Layer 6] Do not echo back user input in error details.
                throw new UserAlreadyExistsException("username already exists");
            }
            if (userRepository.existsByEmailIgnoreCase(normalizedEmail)) {
                throw new UserAlreadyExistsException("email already exists");
            }

            // SECURITY: [Layer 3] Password hashing via Spring Security encoder; never store plaintext.
            // Note: some encoders may create temporary Strings internally; we still minimize the caller secret lifetime.
            String passwordHash = passwordEncoder.encode(CharBuffer.wrap(password));

            User user = User.builder()
                    .username(normalizedUsername)
                    .email(normalizedEmail)
                    .passwordHash(passwordHash)
                    .role(UserRole.USER)
                    .status(AccountStatus.ACTIVE)
                    .failedLoginAttempts(0)
                    .lockoutUntil(null)
                    .build();

            return userRepository.save(user);
        } finally {
            SecretWiper.wipe(password);
        }
    }

    @Transactional
    public void changePassword(long userId, char[] currentPassword, char[] newPassword) {
        try {
            User user = userRepository.findById(userId).orElseThrow(AuthenticationFailedException::new);
            if (user.getStatus() != AccountStatus.ACTIVE) {
                throw new AccountDisabledException();
            }

            boolean ok = passwordEncoder.matches(CharBuffer.wrap(currentPassword), user.getPasswordHash());
            if (!ok) {
                throw new AuthenticationFailedException();
            }

            validatePasswordPolicy(newPassword);
            if (hibpProperties.enabled()) {
                // SECURITY: [Layer 6] Optional breached password check via k-anonymity.
                if (hibpPasswordChecker.isBreached(newPassword)) {
                    throw new WeakPasswordException();
                }
            }

            // SECURITY: [Layer 3] Re-hash new password; clear lockout counters.
            String newHash = passwordEncoder.encode(CharBuffer.wrap(newPassword));
            user.setPasswordHash(newHash);
            user.setFailedLoginAttempts(0);
            user.setLockoutUntil(null);
            userRepository.save(user);
        } finally {
            SecretWiper.wipe(currentPassword);
            SecretWiper.wipe(newPassword);
        }
    }

    @Transactional
    public AuthToken login(String identifier, char[] password) {
        try {
            User user = authenticateByPassword(identifier, password);
            return issueJwt(user);
        } finally {
            SecretWiper.wipe(password);
        }
    }

    @Transactional
    public User authenticateByPassword(String identifier, char[] password) {
        String normalizedIdentifier = normalizeIdentifier(identifier);
        Instant now = Instant.now(clock);

        Optional<User> userOpt = findByIdentifier(normalizedIdentifier);
        if (userOpt.isEmpty()) {
            throw new AuthenticationFailedException();
        }

        User user = userOpt.get();
        if (user.getStatus() != AccountStatus.ACTIVE) {
            throw new AccountDisabledException();
        }

        Instant lockoutUntil = user.getLockoutUntil();
        if (lockoutUntil != null && now.isBefore(lockoutUntil)) {
            throw new AccountLockedException(lockoutUntil);
        }

        boolean ok = passwordEncoder.matches(CharBuffer.wrap(password), user.getPasswordHash());
        if (!ok) {
            int next = Math.addExact(user.getFailedLoginAttempts(), 1);
            user.setFailedLoginAttempts(next);

            if (next >= authProperties.maxFailedAttempts()) {
                Duration lockout = authProperties.lockoutDuration();
                user.setLockoutUntil(now.plus(lockout));
                userRepository.save(user);
                throw new AccountLockedException(user.getLockoutUntil());
            }

            userRepository.save(user);
            throw new AuthenticationFailedException();
        }

        user.setFailedLoginAttempts(0);
        user.setLockoutUntil(null);
        return userRepository.save(user);
    }

    public AuthToken issueJwt(User user) {
        Instant now = Instant.now(clock);
        return issueJwtAt(user, now);
    }

    private AuthToken issueJwtAt(User user, Instant now) {
        Instant expiresAt = now.plus(jwtProperties.ttl());
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(jwtProperties.issuer())
                .issuedAt(now)
                .expiresAt(expiresAt)
                .audience(java.util.List.of(jwtProperties.audience()))
                .subject(String.valueOf(user.getId()))
                .claim("roles", java.util.List.of(user.getRole().name()))
                .claim("username", user.getUsername())
                .build();

        String tokenValue = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        return new AuthToken(tokenValue, expiresAt);
    }

    private Optional<User> findByIdentifier(String identifier) {
        // SECURITY: [Layer 6] Avoid ambiguous normalization; try both email + username (case-insensitive).
        boolean looksLikeEmail = identifier.contains("@");
        if (looksLikeEmail) {
            Optional<User> byEmail = userRepository.findByEmailIgnoreCase(identifier);
            return byEmail.isPresent() ? byEmail : userRepository.findByUsernameIgnoreCase(identifier);
        }
        Optional<User> byUsername = userRepository.findByUsernameIgnoreCase(identifier);
        return byUsername.isPresent() ? byUsername : userRepository.findByEmailIgnoreCase(identifier);
    }

    private static String normalizeEmail(String email) {
        String trimmed = normalizeRequired(email, "email");
        String lower = trimmed.toLowerCase(Locale.ROOT);
        // SECURITY: [Layer 6] Basic email length guard; deeper validation is handled by Bean Validation in controller DTO.
        if (lower.length() > 320) {
            throw new IllegalArgumentException("email is too long");
        }
        return lower;
    }

    private static String normalizeUsername(String username) {
        String trimmed = normalizeRequired(username, "username");
        if (trimmed.length() > 64) {
            throw new IllegalArgumentException("username is too long");
        }
        return trimmed;
    }

    private static String normalizeIdentifier(String identifier) {
        return normalizeRequired(identifier, "identifier");
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

    public static void validatePasswordPolicy(char[] password) {
        // SECURITY: [Layer 6] Fail closed: enforce minimum length; allow full Unicode; avoid arbitrary complexity rules.
        if (password == null || password.length < 12) {
            throw new WeakPasswordException();
        }
        boolean allWhitespace = true;
        for (char c : password) {
            if (!Character.isWhitespace(c)) {
                allWhitespace = false;
                break;
            }
        }
        if (allWhitespace) {
            throw new WeakPasswordException();
        }
    }

    public record AuthToken(String token, Instant expiresAt) {}

    @Transactional(readOnly = true)
    public User getUserByIdInternal(long userId) {
        return userRepository.findById(userId).orElseThrow(AuthenticationFailedException::new);
    }
}

