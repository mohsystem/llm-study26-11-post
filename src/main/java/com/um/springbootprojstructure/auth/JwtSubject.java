package com.um.springbootprojstructure.auth;

import org.springframework.security.oauth2.jwt.Jwt;

public final class JwtSubject {
    private JwtSubject() {}

    public static long requireUserId(Jwt jwt) {
        // SECURITY: [Layer 1] Never trust unchecked casts from JWT claims; validate types and ranges.
        if (jwt == null) {
            throw new AuthenticationFailedException();
        }
        String sub = jwt.getSubject();
        if (sub == null || sub.isBlank()) {
            throw new AuthenticationFailedException();
        }
        try {
            long id = Long.parseLong(sub);
            if (id <= 0) {
                throw new AuthenticationFailedException();
            }
            return id;
        } catch (NumberFormatException ex) {
            throw new AuthenticationFailedException();
        }
    }
}

