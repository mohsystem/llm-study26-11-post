package com.um.springbootprojstructure.admin.directory;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Validated
@RequestMapping(path = "/api/admin/directory", produces = MediaType.APPLICATION_JSON_VALUE)
public class DirectoryController {
    private final DirectoryLookupService directoryService;

    public DirectoryController(DirectoryLookupService directoryService) {
        this.directoryService = directoryService;
    }

    @GetMapping("/user-search")
    @PreAuthorize("hasRole('ADMIN')") // SECURITY: [Layer 6] Admin-only.
    public List<DirectoryUserResponse> userSearch(
            @RequestParam("dc")
            @NotBlank
            @Size(max = 253)
            @Pattern(regexp = "^[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+$")
            String dc,

            @RequestParam("username")
            @NotBlank
            @Size(max = 64)
            @Pattern(regexp = "^[A-Za-z0-9._-]{1,64}$")
            String username
    ) {
        return directoryService.searchUser(dc, username);
    }
}

