package com.um.springbootprojstructure.auth.mfa;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SmsGatewayConfiguration {

    @Bean
    @ConditionalOnMissingBean(SmsGateway.class)
    SmsGateway noopSmsGateway() {
        // SECURITY: [Layer 6] Default to no-op gateway unless explicitly enabled/configured.
        return new NoopSmsGateway();
    }
}

