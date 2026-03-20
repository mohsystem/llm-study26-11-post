package com.um.springbootprojstructure.user;

public class DocumentNotFoundException extends RuntimeException {
    public DocumentNotFoundException(long userId) {
        super("Document not found");
    }
}

