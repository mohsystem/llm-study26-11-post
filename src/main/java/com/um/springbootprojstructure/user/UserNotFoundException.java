package com.um.springbootprojstructure.user;

public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(Long id) {
        super("User not found: id=" + id);
    }

    public UserNotFoundException(String field, String value) {
        super("User not found: " + field + "=" + value);
    }
}

