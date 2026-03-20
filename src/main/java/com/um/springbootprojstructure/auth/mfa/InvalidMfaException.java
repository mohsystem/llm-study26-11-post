package com.um.springbootprojstructure.auth.mfa;

public class InvalidMfaException extends RuntimeException {
    public InvalidMfaException() {
        super("Invalid MFA code");
    }
}

