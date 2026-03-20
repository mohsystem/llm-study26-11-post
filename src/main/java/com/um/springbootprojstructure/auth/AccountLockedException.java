package com.um.springbootprojstructure.auth;

import java.time.Instant;

public class AccountLockedException extends RuntimeException {
    private final Instant lockedUntil;

    public AccountLockedException(Instant lockedUntil) {
        super("Account is temporarily locked");
        this.lockedUntil = lockedUntil;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }
}

