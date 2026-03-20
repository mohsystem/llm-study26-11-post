package com.um.springbootprojstructure.auth;

public class AuthenticationFailedException extends RuntimeException {
    public AuthenticationFailedException() {
        super("Invalid credentials");
    }
}

