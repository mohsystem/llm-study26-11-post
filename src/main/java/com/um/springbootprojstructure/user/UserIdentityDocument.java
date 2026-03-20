package com.um.springbootprojstructure.user;

import jakarta.persistence.Basic;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(
        name = "user_identity_documents",
        uniqueConstraints = @UniqueConstraint(name = "uk_user_identity_documents_user", columnNames = "user_id"),
        indexes = @Index(name = "idx_user_identity_documents_user", columnList = "user_id")
)
@Getter
@Setter
@NoArgsConstructor
public class UserIdentityDocument {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "content_type", nullable = false, length = 100)
    private String contentType;

    @Column(name = "uploaded_at", nullable = false)
    private Instant uploadedAt;

    // SECURITY: [Layer 6] Store document content as BLOB; never trust user-supplied filenames/paths.
    @Lob
    @Basic(fetch = FetchType.LAZY)
    @Column(name = "content", nullable = false)
    private byte[] content;
}

