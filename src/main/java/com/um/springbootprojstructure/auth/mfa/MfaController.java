package com.um.springbootprojstructure.auth.mfa;

import com.um.springbootprojstructure.auth.AuthService;
import com.um.springbootprojstructure.auth.mfa.dto.MfaChallengeRequest;
import com.um.springbootprojstructure.auth.mfa.dto.MfaChallengeResponse;
import com.um.springbootprojstructure.auth.mfa.dto.MfaVerifyRequest;
import com.um.springbootprojstructure.auth.mfa.dto.MfaVerifyResponse;
import com.um.springbootprojstructure.security.SecretWiper;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/auth/mfa", produces = MediaType.APPLICATION_JSON_VALUE)
public class MfaController {
    private final MfaService mfaService;

    public MfaController(MfaService mfaService) {
        this.mfaService = mfaService;
    }

    @PostMapping(path = "/challenge", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<MfaChallengeResponse> challenge(@Valid @RequestBody MfaChallengeRequest request) {
        mfaService.challenge(request.identifier(), request.password());
        return ResponseEntity.ok(new MfaChallengeResponse("CHALLENGE_SENT"));
    }

    @PostMapping(path = "/verify", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<MfaVerifyResponse> verify(@Valid @RequestBody MfaVerifyRequest request) {
        char[] code = request.code().toCharArray();
        try {
            AuthService.AuthToken token = mfaService.verify(request.identifier(), code);
            return ResponseEntity.ok(new MfaVerifyResponse("VERIFIED", "Bearer", token.token(), token.expiresAt()));
        } finally {
            // SECURITY: [Layer 5] Wipe OTP copy best-effort.
            SecretWiper.wipe(code);
        }
    }
}

