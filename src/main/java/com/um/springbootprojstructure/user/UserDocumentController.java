package com.um.springbootprojstructure.user;

import com.um.springbootprojstructure.auth.JwtSubject;
import com.um.springbootprojstructure.user.dto.DocumentUpdateResponse;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import java.util.Collection;
import org.springframework.http.CacheControl;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping(path = "/api/users", produces = MediaType.APPLICATION_JSON_VALUE)
public class UserDocumentController {
    private final UserRepository userRepository;
    private final UserDocumentService documentService;

    public UserDocumentController(UserRepository userRepository, UserDocumentService documentService) {
        this.userRepository = userRepository;
        this.documentService = documentService;
    }

    @GetMapping(path = "/{publicRef}/document", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<byte[]> getDocument(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @NotBlank @Pattern(regexp = "^[A-Za-z0-9_-]{16,64}$") String publicRef
    ) {
        User user = userRepository.findByPublicRef(publicRef).orElseThrow(() -> new UserNotFoundException("publicRef", publicRef));
        enforceOwnerOrAdmin(jwt, user.getId());

        UserIdentityDocument doc = documentService.getDocument(user.getId());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType(doc.getContentType()));
        headers.setCacheControl(CacheControl.noStore());
        headers.setContentDisposition(ContentDisposition.attachment().filename("identity-document").build());
        headers.setContentLength(doc.getContent().length);

        return ResponseEntity.ok().headers(headers).body(doc.getContent());
    }

    @PutMapping(path = "/{publicRef}/document", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<DocumentUpdateResponse> putDocument(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable @NotBlank @Pattern(regexp = "^[A-Za-z0-9_-]{16,64}$") String publicRef,
            @RequestPart("file") MultipartFile file
    ) {
        User user = userRepository.findByPublicRef(publicRef).orElseThrow(() -> new UserNotFoundException("publicRef", publicRef));
        enforceOwnerOrAdmin(jwt, user.getId());

        documentService.replaceDocument(user.getId(), file);
        return ResponseEntity.ok(new DocumentUpdateResponse("DOCUMENT_UPDATED"));
    }

    private static void enforceOwnerOrAdmin(Jwt jwt, long targetUserId) {
        // SECURITY: [Layer 6] Prevent horizontal privilege escalation: only owner or admin.
        long requesterId = JwtSubject.requireUserId(jwt);
        if (requesterId == targetUserId) {
            return;
        }
        Collection<String> roles = jwt.getClaimAsStringList("roles");
        if (roles != null && roles.stream().anyMatch(r -> "ADMIN".equalsIgnoreCase(r))) {
            return;
        }
        throw new AccessDeniedException("Forbidden");
    }
}

