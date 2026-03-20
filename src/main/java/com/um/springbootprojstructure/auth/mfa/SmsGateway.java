package com.um.springbootprojstructure.auth.mfa;

public interface SmsGateway {
    // SECURITY: [Layer 6] Do not log OTPs; delivery must be out-of-band.
    void sendOtp(String phoneNumber, String message);
}

