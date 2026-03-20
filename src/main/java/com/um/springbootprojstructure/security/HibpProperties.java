package com.um.springbootprojstructure.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.password.hibp")
public record HibpProperties(boolean enabled) {}

