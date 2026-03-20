package com.um.springbootprojstructure.user;

public class UnsupportedDocumentTypeException extends RuntimeException {
    public UnsupportedDocumentTypeException() {
        super("Unsupported document type");
    }
}

