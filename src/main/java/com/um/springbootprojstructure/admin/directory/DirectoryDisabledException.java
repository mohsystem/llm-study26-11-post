package com.um.springbootprojstructure.admin.directory;

public class DirectoryDisabledException extends RuntimeException {
    public DirectoryDisabledException() {
        super("Directory lookup is disabled");
    }
}

