package com.um.springbootprojstructure.admin.directory;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DirectoryLookupConfiguration {

    @Bean
    @ConditionalOnMissingBean(DirectoryLookupService.class)
    DirectoryLookupService disabledDirectoryLookupService() {
        // SECURITY: [Layer 6] Default fail-closed behavior unless LDAP integration is explicitly enabled/configured.
        return new DisabledDirectoryLookupService();
    }
}

