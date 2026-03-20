package com.um.springbootprojstructure.security;

import java.lang.ref.Reference;
import java.util.Arrays;

public final class SecretWiper {
    private SecretWiper() {}

    public static void wipe(char[] secret) {
        if (secret == null) {
            return;
        }
        // SECURITY: [Layer 5] Wipe secret and fence to reduce JIT dead-store elimination risk.
        Arrays.fill(secret, '\0');
        Reference.reachabilityFence(secret);
    }
}

