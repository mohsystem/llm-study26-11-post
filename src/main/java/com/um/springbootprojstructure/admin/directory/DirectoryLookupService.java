package com.um.springbootprojstructure.admin.directory;

import java.util.List;

public interface DirectoryLookupService {
    List<DirectoryUserResponse> searchUser(String domain, String username);
}

