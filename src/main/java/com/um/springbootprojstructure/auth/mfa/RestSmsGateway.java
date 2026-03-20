package com.um.springbootprojstructure.auth.mfa;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(prefix = "security.mfa.sms", name = "enabled", havingValue = "true")
public class RestSmsGateway implements SmsGateway {
    private final SmsGatewayProperties properties;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;

    public RestSmsGateway(SmsGatewayProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(defaultIfNull(properties.connectTimeout(), Duration.ofSeconds(5)))
                .followRedirects(HttpClient.Redirect.NEVER) // SECURITY: [Layer 2] Avoid redirect chains.
                .build();

        // SECURITY: [Layer 2/6] Fail closed if misconfigured.
        validateBaseUrl(properties.baseUrl());
        validatePath(properties.sendPath());
    }

    @Override
    public void sendOtp(String phoneNumber, String message) {
        try {
            URI endpoint = properties.baseUrl().resolve(properties.sendPath());
            String json = objectMapper.writeValueAsString(Map.of(
                    "to", phoneNumber,
                    "message", message
            ));

            HttpRequest req = HttpRequest.newBuilder(endpoint)
                    .timeout(defaultIfNull(properties.requestTimeout(), Duration.ofSeconds(5)))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

            HttpResponse<Void> resp = httpClient.send(req, HttpResponse.BodyHandlers.discarding());
            if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
                // SECURITY: [Layer 6] Do not leak gateway response body; fail closed.
                throw new IllegalStateException("SMS gateway returned non-2xx");
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to send OTP", e);
        }
    }

    private static void validateBaseUrl(URI baseUrl) {
        if (baseUrl == null) {
            throw new IllegalStateException("SMS baseUrl is required");
        }
        if (!"https".equalsIgnoreCase(baseUrl.getScheme())) {
            throw new IllegalStateException("SMS baseUrl must be https");
        }
        if (baseUrl.getHost() == null || baseUrl.getHost().isBlank()) {
            throw new IllegalStateException("SMS baseUrl host is required");
        }
        if (baseUrl.getUserInfo() != null) {
            throw new IllegalStateException("SMS baseUrl must not contain user info");
        }
        if (baseUrl.getFragment() != null) {
            throw new IllegalStateException("SMS baseUrl must not contain fragment");
        }
    }

    private static void validatePath(String path) {
        if (path == null || path.isBlank() || !path.startsWith("/")) {
            throw new IllegalStateException("SMS sendPath must start with '/'");
        }
    }

    private static Duration defaultIfNull(Duration v, Duration fallback) {
        return v == null ? fallback : v;
    }
}

