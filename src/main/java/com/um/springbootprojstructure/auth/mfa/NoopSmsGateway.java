package com.um.springbootprojstructure.auth.mfa;

public class NoopSmsGateway implements SmsGateway {
    @Override
    public void sendOtp(String phoneNumber, String message) {
        // SECURITY: [Layer 6] Intentionally no-op. Do NOT log OTPs.
    }
}

