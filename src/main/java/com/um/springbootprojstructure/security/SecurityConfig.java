package com.um.springbootprojstructure.security;

import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.um.springbootprojstructure.auth.mfa.SmsGatewayProperties;
import com.um.springbootprojstructure.user.UserRole;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.Assert;

@Configuration
@EnableMethodSecurity
@EnableConfigurationProperties({
        JwtProperties.class,
        AuthProperties.class,
        HibpProperties.class,
        PasswordResetProperties.class,
        IdentityDocumentProperties.class,
        MfaProperties.class,
        SmsGatewayProperties.class
})
public class SecurityConfig {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        // SECURITY: [Layer 3] Delegating encoder supports hash agility; default to bcrypt.
        // SECURITY: [Layer 6] Enforce bcrypt strength >= 12 (OWASP baseline).
        BCryptPasswordEncoder bcrypt12 = new BCryptPasswordEncoder(12);
        DelegatingPasswordEncoder delegating = new DelegatingPasswordEncoder(
                "bcrypt",
                java.util.Map.of("bcrypt", bcrypt12)
        );
        // SECURITY: [Layer 6] If legacy hashes lack an id prefix, match them using bcrypt(12) only.
        delegating.setDefaultPasswordEncoderForMatches(bcrypt12);
        return delegating;
    }

    @Bean
    KeyPair jwtSigningKeyPair() {
        try {
            // SECURITY: [Layer 2] Use SecureRandom and RSA >= 2048-bit for JWT signing.
            // SECURITY: [Layer 6] For production, replace this ephemeral key with an externally managed keystore/key pair
            // (e.g., mounted secret file / HSM) to avoid token invalidation on restart.
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(3072, SecureRandom.getInstanceStrong());
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize JWT signing keys", e);
        }
    }

    @Bean
    JwtEncoder jwtEncoder(KeyPair jwtSigningKeyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) jwtSigningKeyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) jwtSigningKeyPair.getPrivate();

        String kid = keyId(publicKey);
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(kid)
                .build();

        // SECURITY: [Layer 3] In-memory JWKSet avoids network fetches (no SSRF surface).
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(rsaKey)));
    }

    @Bean
    JwtDecoder jwtDecoder(KeyPair jwtSigningKeyPair, JwtProperties jwtProperties) {
        RSAPublicKey publicKey = (RSAPublicKey) jwtSigningKeyPair.getPublic();
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey).build();

        // SECURITY: [Layer 3] Validate iss/aud/exp/nbf and pin expected algorithm.
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(jwtProperties.issuer());
        OAuth2TokenValidator<Jwt> audience = new JwtClaimValidator<List<String>>(
                "aud",
                aud -> aud != null && aud.contains(jwtProperties.audience())
        );
        OAuth2TokenValidator<Jwt> algPinned = jwt -> {
            Object alg = jwt.getHeaders().get("alg");
            if (Objects.equals(alg, "RS256")) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Unexpected JWT alg", null));
        };

        decoder.setJwtValidator(new org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator<>(
                withIssuer,
                audience,
                algPinned
        ));
        return decoder;
    }

    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter jwtAuthenticationConverter
    ) throws Exception {
        // SECURITY: [Layer 3] Stateless API using JWT session tokens in JSON; CSRF is disabled accordingly.
        http.csrf(csrf -> csrf.disable());
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.POST,
                        "/api/auth/register",
                        "/api/auth/login",
                        "/api/auth/mfa/challenge",
                        "/api/auth/mfa/verify",
                        "/api/auth/reset-request",
                        "/api/auth/reset-confirm"
                ).permitAll()
                .requestMatchers("/error").permitAll()
                .anyRequest().authenticated()
        );

        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter)));

        http.headers(headers -> headers
                // SECURITY: [Layer 3] Keep default hardening headers enabled; add explicit HSTS + CSP for APIs.
                .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000))
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                        "default-src 'none'; base-uri 'none'; frame-ancestors 'none'"
                ))
                .frameOptions(frame -> frame.deny())
        );

        return http.build();
    }

    @Bean
    org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter jwtAuthenticationConverter() {
        org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter converter =
                new org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            // SECURITY: [Layer 6] Fail-closed: only map allow-listed roles from "roles" claim.
            Object claim = jwt.getClaims().get("roles");
            Collection<?> raw = (claim instanceof Collection<?> c) ? c : List.of();

            List<GrantedAuthority> authorities = new ArrayList<>(raw.size());
            for (Object v : raw) {
                if (v == null) {
                    continue;
                }
                String roleName = String.valueOf(v).trim().toUpperCase(Locale.ROOT);
                try {
                    UserRole role = UserRole.valueOf(roleName);
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + role.name()));
                } catch (IllegalArgumentException ignored) {
                    // SECURITY: [Layer 6] Unknown role is ignored (no privilege escalation).
                }
            }
            return authorities;
        });
        return converter;
    }

    private static String keyId(RSAPublicKey publicKey) {
        try {
            // SECURITY: [Layer 2] Use SHA-256 for non-secret key identifier (not a security boundary).
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(publicKey.getEncoded());
            String hex = bytesToHex(digest);
            return hex.substring(0, 16);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to derive key id", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        Assert.notNull(bytes, "bytes must not be null");
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}

