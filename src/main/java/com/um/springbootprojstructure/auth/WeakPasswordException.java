package com.um.springbootprojstructure.auth;

public class WeakPasswordException extends RuntimeException {
    public WeakPasswordException() {
        super("Password does not meet policy requirements");
    }
}

