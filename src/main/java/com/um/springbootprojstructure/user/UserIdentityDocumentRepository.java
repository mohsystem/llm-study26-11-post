package com.um.springbootprojstructure.user;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserIdentityDocumentRepository extends JpaRepository<UserIdentityDocument, Long> {
    Optional<UserIdentityDocument> findByUserId(Long userId);
    boolean existsByUserId(Long userId);
    void deleteByUserId(Long userId);
}

