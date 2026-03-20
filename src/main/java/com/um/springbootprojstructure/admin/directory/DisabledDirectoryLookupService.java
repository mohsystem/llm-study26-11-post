package com.um.springbootprojstructure.admin.directory;

import java.util.List;

public class DisabledDirectoryLookupService implements DirectoryLookupService {
    @Override
    public List<DirectoryUserResponse> searchUser(String domain, String username) {
        // SECURITY: [Layer 6] Fail closed when directory integration not configured.
        throw new DirectoryDisabledException();
    }
}

