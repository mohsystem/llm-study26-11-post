package com.um.springbootprojstructure.admin.directory;

public record DirectoryUserResponse(
        String uid,
        String cn,
        String mail,
        String dn
) {}

