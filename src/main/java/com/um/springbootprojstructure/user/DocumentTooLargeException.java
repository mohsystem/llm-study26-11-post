package com.um.springbootprojstructure.user;

public class DocumentTooLargeException extends RuntimeException {
    public DocumentTooLargeException() {
        super("Document too large");
    }
}

