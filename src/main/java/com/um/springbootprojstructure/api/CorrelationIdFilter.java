package com.um.springbootprojstructure.api;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class CorrelationIdFilter extends OncePerRequestFilter {
    public static final String ATTRIBUTE_NAME = "correlationId";
    private static final String HEADER_NAME = "X-Correlation-Id";
    private static final Pattern ALLOWED = Pattern.compile("^[A-Za-z0-9_-]{16,64}$");
    private static final SecureRandom RNG = new SecureRandom();

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String cid = request.getHeader(HEADER_NAME);
        if (cid == null || !ALLOWED.matcher(cid).matches()) {
            cid = generate();
        }

        // SECURITY: [Layer 6] Correlation IDs are not auth tokens; still treat as untrusted and normalize.
        request.setAttribute(ATTRIBUTE_NAME, cid);
        response.setHeader(HEADER_NAME, cid);
        filterChain.doFilter(request, response);
    }

    private static String generate() {
        byte[] bytes = new byte[16];
        RNG.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}

