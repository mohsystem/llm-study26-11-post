package com.um.springbootprojstructure.auth;

public interface PasswordResetNotificationSender {
    // SECURITY: [Layer 6] Reset tokens must be delivered out-of-band (email/SMS) and must never be logged.
    void sendResetToken(UserAccountSnapshot account, String resetToken);

    record UserAccountSnapshot(long id, String username, String email) {}
}

