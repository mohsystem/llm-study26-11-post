package com.um.springbootprojstructure.auth;

import org.springframework.stereotype.Component;

@Component
public class NoopPasswordResetNotificationSender implements PasswordResetNotificationSender {
    @Override
    public void sendResetToken(UserAccountSnapshot account, String resetToken) {
        // SECURITY: [Layer 6] Intentionally no-op. Do NOT log reset tokens.
    }
}

