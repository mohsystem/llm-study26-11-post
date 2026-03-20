package com.um.springbootprojstructure.user;

import org.springframework.data.jpa.domain.Specification;

public final class UserSpecifications {
    private UserSpecifications() {}

    public static Specification<User> hasRole(UserRole role) {
        return (root, query, cb) -> cb.equal(root.get("role"), role);
    }

    public static Specification<User> hasStatus(AccountStatus status) {
        return (root, query, cb) -> cb.equal(root.get("status"), status);
    }
}

