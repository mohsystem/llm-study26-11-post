package com.um.springbootprojstructure.auth;

public class InvalidResetTokenException extends RuntimeException {
    public InvalidResetTokenException() {
        super("Invalid or expired reset token");
    }
}

