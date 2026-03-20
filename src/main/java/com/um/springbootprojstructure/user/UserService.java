package com.um.springbootprojstructure.user;

import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User createUser(User user) {
        String email = normalize(user.getEmail());
        String username = normalize(user.getUsername());

        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("email is required");
        }
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("username is required");
        }
        if (user.getPasswordHash() == null || user.getPasswordHash().isBlank()) {
            throw new IllegalArgumentException("passwordHash is required");
        }

        if (userRepository.existsByEmailIgnoreCase(email)) {
            throw new UserAlreadyExistsException("email already exists: " + email);
        }
        if (userRepository.existsByUsernameIgnoreCase(username)) {
            throw new UserAlreadyExistsException("username already exists: " + username);
        }

        user.setEmail(email);
        user.setUsername(username);
        return userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public User getUserById(Long id) {
        return userRepository.findById(id).orElseThrow(() -> new UserNotFoundException(id));
    }

    @Transactional(readOnly = true)
    public User getUserByEmail(String email) {
        String normalized = normalize(email);
        if (normalized == null || normalized.isBlank()) {
            throw new IllegalArgumentException("email is required");
        }
        return userRepository
                .findByEmailIgnoreCase(normalized)
                .orElseThrow(() -> new UserNotFoundException("email", normalized));
    }

    @Transactional(readOnly = true)
    public List<User> listUsers() {
        return userRepository.findAll();
    }

    public User updateUser(Long id, User updates) {
        User existing = getUserById(id);

        if (updates.getEmail() != null) {
            String email = normalize(updates.getEmail());
            if (email.isBlank()) {
                throw new IllegalArgumentException("email cannot be blank");
            }
            if (!email.equalsIgnoreCase(existing.getEmail()) && userRepository.existsByEmailIgnoreCase(email)) {
                throw new UserAlreadyExistsException("email already exists: " + email);
            }
            existing.setEmail(email);
        }

        if (updates.getUsername() != null) {
            String username = normalize(updates.getUsername());
            if (username.isBlank()) {
                throw new IllegalArgumentException("username cannot be blank");
            }
            if (!username.equalsIgnoreCase(existing.getUsername())
                    && userRepository.existsByUsernameIgnoreCase(username)) {
                throw new UserAlreadyExistsException("username already exists: " + username);
            }
            existing.setUsername(username);
        }

        if (updates.getPasswordHash() != null) {
            String ph = updates.getPasswordHash();
            if (ph.isBlank()) {
                throw new IllegalArgumentException("passwordHash cannot be blank");
            }
            existing.setPasswordHash(ph);
        }

        return userRepository.save(existing);
    }

    public void deleteUser(Long id) {
        if (!userRepository.existsById(id)) {
            throw new UserNotFoundException(id);
        }
        userRepository.deleteById(id);
    }

    private static String normalize(String value) {
        return value == null ? null : value.trim();
    }
}

