package com.um.springbootprojstructure.auth.apikey;

public class ApiKeyNotFoundException extends RuntimeException {
    public ApiKeyNotFoundException() {
        super("API key not found");
    }
}

