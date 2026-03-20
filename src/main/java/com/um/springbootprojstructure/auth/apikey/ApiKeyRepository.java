package com.um.springbootprojstructure.auth.apikey;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ApiKeyRepository extends JpaRepository<ApiKey, Long> {
    List<ApiKey> findByOwnerUserIdOrderByCreatedAtDesc(Long ownerUserId);
    Optional<ApiKey> findByIdAndOwnerUserId(Long id, Long ownerUserId);
}

