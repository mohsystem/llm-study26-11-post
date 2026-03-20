package com.um.springbootprojstructure.user;

import com.um.springbootprojstructure.user.dto.UserSummaryResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserQueryService {
    private final UserRepository userRepository;

    public UserQueryService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional(readOnly = true)
    public Page<UserSummaryResponse> listUsers(int page, int size, UserRole role, AccountStatus status) {
        Pageable pageable = PageRequest.of(page, size);
        Specification<User> spec = (root, query, cb) -> cb.conjunction();
        if (role != null) {
            spec = spec.and(UserSpecifications.hasRole(role));
        }
        if (status != null) {
            spec = spec.and(UserSpecifications.hasStatus(status));
        }

        return userRepository.findAll(spec, pageable).map(u -> new UserSummaryResponse(
                u.getId(),
                u.getUsername(),
                u.getEmail(),
                u.getRole(),
                u.getStatus(),
                u.getCreatedAt()
        ));
    }
}

