package com.um.springbootprojstructure.user;

import java.security.SecureRandom;
import java.util.Base64;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class UserPublicRefBackfill implements ApplicationRunner {
    private static final SecureRandom RNG = new SecureRandom();

    private final UserRepository userRepository;

    public UserPublicRefBackfill(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        // SECURITY: [Layer 6] Ensure legacy rows get a non-guessable publicRef for safe URL exposure.
        userRepository.findAll().forEach(user -> {
            if (user.getPublicRef() == null || user.getPublicRef().isBlank()) {
                user.setPublicRef(generateUniquePublicRef());
                userRepository.save(user);
            }
        });
    }

    private String generateUniquePublicRef() {
        // SECURITY: [Layer 2] Retry on rare collisions; fail closed on excessive retries.
        for (int i = 0; i < 10; i++) {
            String ref = generate();
            if (!userRepository.existsByPublicRef(ref)) {
                return ref;
            }
        }
        throw new IllegalStateException("Unable to generate unique publicRef");
    }

    private static String generate() {
        byte[] bytes = new byte[16];
        RNG.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}

