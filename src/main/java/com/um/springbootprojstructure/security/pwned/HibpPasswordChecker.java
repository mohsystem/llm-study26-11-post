package com.um.springbootprojstructure.security.pwned;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import org.springframework.stereotype.Component;

@Component
public class HibpPasswordChecker {
    private static final URI BASE = URI.create("https://api.pwnedpasswords.com");
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);
    private static final int MAX_BODY_CHARS = 2_000_000;

    private final HttpClient httpClient;

    public HibpPasswordChecker() {
        // SECURITY: [Layer 2] Short timeouts, no redirects (avoid open redirect chains), default TLS + hostname verification.
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    public boolean isBreached(char[] password) {
        if (password == null) {
            throw new IllegalArgumentException("password is required");
        }

        String sha1Upper = sha1HexUpper(password);
        String prefix = sha1Upper.substring(0, 5);
        String suffix = sha1Upper.substring(5);

        // SECURITY: [Layer 2] Strict allow-list: fixed host + path; no user-controlled URL (prevents SSRF).
        URI uri = BASE.resolve("/range/" + prefix);
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(REQUEST_TIMEOUT)
                .header("User-Agent", "user-management/1.0")
                .GET()
                .build();

        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() != 200) {
                // SECURITY: [Layer 6] Fail closed when the breached-password check is enabled.
                throw new IllegalStateException("HIBP check failed with status " + response.statusCode());
            }

            String body = response.body();
            if (body == null || body.length() > MAX_BODY_CHARS) {
                throw new IllegalStateException("HIBP response too large or empty");
            }

            // Each line: <HASH_SUFFIX>:<COUNT>
            String[] lines = body.split("\r?\n");
            for (String line : lines) {
                int colon = line.indexOf(':');
                if (colon <= 0) {
                    continue;
                }
                String lineSuffix = line.substring(0, colon).trim();
                if (lineSuffix.equalsIgnoreCase(suffix)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            throw new IllegalStateException("HIBP check failed", e);
        }
    }

    private static String sha1HexUpper(char[] password) {
        byte[] bytes = null;
        try {
            CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder();
            ByteBuffer bb = encoder.encode(CharBuffer.wrap(password));
            bytes = new byte[bb.remaining()];
            bb.get(bytes);

            // SECURITY: [Layer 2] HIBP k-anonymity API requires SHA-1 input format.
            // This is NOT used for integrity, authentication, or long-term storage; only to query breach data.
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(bytes);
            return HexFormat.of().formatHex(digest).toUpperCase();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute HIBP hash", e);
        } finally {
            if (bytes != null) {
                // SECURITY: [Layer 5] Wipe transient password bytes best-effort.
                Arrays.fill(bytes, (byte) 0);
            }
        }
    }
}

