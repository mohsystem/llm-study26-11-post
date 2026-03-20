package com.um.springbootprojstructure.user;

import com.um.springbootprojstructure.security.IdentityDocumentProperties;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Clock;
import java.time.Instant;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

@Service
public class UserDocumentService {
    private final UserIdentityDocumentRepository documentRepository;
    private final IdentityDocumentProperties properties;
    private final Clock clock;

    public UserDocumentService(
            UserIdentityDocumentRepository documentRepository,
            IdentityDocumentProperties properties,
            Clock clock
    ) {
        this.documentRepository = documentRepository;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public UserIdentityDocument getDocument(long userId) {
        return documentRepository.findByUserId(userId).orElseThrow(() -> new DocumentNotFoundException(userId));
    }

    @Transactional
    public void replaceDocument(long userId, MultipartFile file) {
        if (file == null) {
            throw new IllegalArgumentException("file is required");
        }

        byte[] bytes = readBounded(file, properties.maxBytes());
        String mime = sniffMime(bytes);

        // SECURITY: [Layer 6] Validate using content sniffing; do not trust client-supplied Content-Type.
        if (mime == null) {
            throw new UnsupportedDocumentTypeException();
        }

        UserIdentityDocument doc = documentRepository.findByUserId(userId).orElseGet(UserIdentityDocument::new);
        doc.setUserId(userId);
        doc.setContentType(mime);
        doc.setUploadedAt(Instant.now(clock));
        doc.setContent(bytes);

        documentRepository.save(doc);
    }

    private static byte[] readBounded(MultipartFile file, long maxBytes) {
        // SECURITY: [Layer 6] Bounded read to prevent OOM / payload inflation.
        if (maxBytes <= 0) {
            throw new IllegalStateException("Invalid maxBytes");
        }
        if (maxBytes > Integer.MAX_VALUE) {
            // SECURITY: [Layer 1] Prevent narrowing overflow into array sizes.
            throw new IllegalStateException("maxBytes too large");
        }

        try (InputStream in = file.getInputStream(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            long total = 0;
            int read;
            while ((read = in.read(buffer)) != -1) {
                total = Math.addExact(total, read);
                if (total > maxBytes) {
                    throw new DocumentTooLargeException();
                }
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read upload", e);
        }
    }

    private static String sniffMime(byte[] bytes) {
        // SECURITY: [Layer 3/6] Minimal, deterministic content sniffing using magic bytes.
        if (bytes == null || bytes.length < 4) {
            return null;
        }
        if (startsWith(bytes, new byte[]{'%', 'P', 'D', 'F', '-' })) {
            return "application/pdf";
        }
        if (bytes.length >= 3 && (bytes[0] & 0xFF) == 0xFF && (bytes[1] & 0xFF) == 0xD8 && (bytes[2] & 0xFF) == 0xFF) {
            return "image/jpeg";
        }
        if (startsWith(bytes, new byte[]{(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})) {
            return "image/png";
        }
        return null;
    }

    private static boolean startsWith(byte[] bytes, byte[] prefix) {
        if (bytes.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (bytes[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }
}

