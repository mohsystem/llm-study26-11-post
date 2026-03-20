package com.um.springbootprojstructure;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.um.springbootprojstructure.auth.PasswordResetNotificationSender;
import com.um.springbootprojstructure.auth.mfa.SmsGateway;
import com.um.springbootprojstructure.admin.directory.DirectoryLookupService;
import com.um.springbootprojstructure.admin.directory.DirectoryUserResponse;
import com.um.springbootprojstructure.user.AccountStatus;
import com.um.springbootprojstructure.user.User;
import com.um.springbootprojstructure.user.UserRepository;
import com.um.springbootprojstructure.user.UserRole;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuthApiTests {

    @Autowired
    MockMvc mvc;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    CapturingResetSender capturingResetSender;

    @Autowired
    CapturingSmsGateway capturingSmsGateway;

    @MockBean
    DirectoryLookupService directoryService;

    @Test
    void register_createsUser_andReturnsIdAndStatus() throws Exception {
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "alice_1",
                                  "email": "alice@example.com",
                                  "password": "correct horse battery staple"
                                }
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNumber())
                .andExpect(jsonPath("$.status").value("CREATED"));
    }

    @Test
    void login_returnsBearerToken_onSuccess() throws Exception {
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "bob_1",
                                  "email": "bob@example.com",
                                  "password": "a very strong passphrase"
                                }
                                """))
                .andExpect(status().isCreated());

        String body = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "identifier": "bob@example.com",
                                  "password": "a very strong passphrase"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.token").isString())
                .andReturn()
                .getResponse()
                .getContentAsString();

        JsonNode json = objectMapper.readTree(body);
        String token = json.get("token").asText();
        if (token.isBlank()) {
            throw new AssertionError("Expected non-empty token");
        }
    }

    @Test
    void usersList_requiresAdminRole() throws Exception {
        userRepository.save(User.builder()
                .username("admin_1")
                .email("admin@example.com")
                .passwordHash(passwordEncoder.encode("admin strong passphrase"))
                .role(UserRole.ADMIN)
                .status(AccountStatus.ACTIVE)
                .failedLoginAttempts(0)
                .lockoutUntil(null)
                .build());

        userRepository.save(User.builder()
                .username("user_1")
                .email("user@example.com")
                .passwordHash(passwordEncoder.encode("user strong passphrase"))
                .role(UserRole.USER)
                .status(AccountStatus.ACTIVE)
                .failedLoginAttempts(0)
                .lockoutUntil(null)
                .build());

        mvc.perform(get("/api/users"))
                .andExpect(status().isUnauthorized());

        String adminLoginBody = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "identifier": "admin@example.com",
                                  "password": "admin strong passphrase"
                                }
                                """))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String adminToken = objectMapper.readTree(adminLoginBody).get("token").asText();

        mvc.perform(get("/api/users?page=0&size=10")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray());

        String userLoginBody = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "identifier": "user@example.com",
                                  "password": "user strong passphrase"
                                }
                                """))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String userToken = objectMapper.readTree(userLoginBody).get("token").asText();

        mvc.perform(get("/api/users?page=0&size=10")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void changePassword_requiresAuthentication() throws Exception {
        mvc.perform(post("/api/auth/change-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "currentPassword": "x",
                                  "newPassword": "correct horse battery staple"
                                }
                                """))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void changePassword_rotatesPassword_andInvalidatesOldPassword() throws Exception {
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "cp_1",
                                  "email": "cp1@example.com",
                                  "password": "a very strong passphrase"
                                }
                                """))
                .andExpect(status().isCreated());

        String loginBody = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "identifier": "cp1@example.com",
                                  "password": "a very strong passphrase"
                                }
                                """))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String token = objectMapper.readTree(loginBody).get("token").asText();

        mvc.perform(post("/api/auth/change-password")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "currentPassword": "a very strong passphrase",
                                  "newPassword": "correct horse battery staple"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PASSWORD_CHANGED"));

        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "identifier": "cp1@example.com",
                                  "password": "a very strong passphrase"
                                }
                                """))
                .andExpect(status().isUnauthorized());

        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "identifier": "cp1@example.com",
                                  "password": "correct horse battery staple"
                                }
                                """))
                .andExpect(status().isOk());
    }

    @Test
    void resetRequest_isEnumerationSafe() throws Exception {
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "rr_1",
                                  "email": "rr1@example.com",
                                  "password": "a very strong passphrase"
                                }
                                """))
                .andExpect(status().isCreated());

        String unknown = mvc.perform(post("/api/auth/reset-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                { "identifier": "does-not-exist@example.com" }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("RESET_REQUESTED"))
                .andReturn().getResponse().getContentAsString();

        String existing = mvc.perform(post("/api/auth/reset-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                { "identifier": "rr1@example.com" }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("RESET_REQUESTED"))
                .andReturn().getResponse().getContentAsString();

        if (!Objects.equals(unknown, existing)) {
            throw new AssertionError("Reset request response must not vary by account existence");
        }
    }

    @Test
    void resetConfirm_resetsPassword_andTokenIsSingleUse() throws Exception {
        capturingResetSender.clear();

        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "pr_1",
                                  "email": "pr1@example.com",
                                  "password": "a very strong passphrase"
                                }
                                """))
                .andExpect(status().isCreated());

        mvc.perform(post("/api/auth/reset-request")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                { "identifier": "pr_1" }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("RESET_REQUESTED"));

        String token = capturingResetSender.requireToken();

        mvc.perform(post("/api/auth/reset-confirm")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "token": "%s",
                                  "newPassword": "correct horse battery staple"
                                }
                                """.formatted(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("RESET_CONFIRMED"));

        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "identifier": "pr1@example.com",
                                  "password": "a very strong passphrase"
                                }
                                """))
                .andExpect(status().isUnauthorized());

        mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "identifier": "pr1@example.com",
                                  "password": "correct horse battery staple"
                                }
                                """))
                .andExpect(status().isOk());

        // SECURITY: [Layer 6] Token must be single-use.
        mvc.perform(post("/api/auth/reset-confirm")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "token": "%s",
                                  "newPassword": "another strong passphrase"
                                }
                                """.formatted(token)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void identityDocument_uploadAndDownload_ownerOnly() throws Exception {
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"doc_1","email":"doc1@example.com","password":"a very strong passphrase"}
                                """))
                .andExpect(status().isCreated());

        String loginBody = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"identifier":"doc1@example.com","password":"a very strong passphrase"}
                                """))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String token = objectMapper.readTree(loginBody).get("token").asText();

        String publicRef = userRepository.findByEmailIgnoreCase("doc1@example.com").orElseThrow().getPublicRef();

        byte[] pdf = "%PDF-1.4\n%âãÏÓ\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        mvc.perform(multipart("/api/users/" + publicRef + "/document")
                        .file("file", pdf)
                        .with(r -> { r.setMethod("PUT"); return r; })
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DOCUMENT_UPDATED"));

        byte[] downloaded = mvc.perform(get("/api/users/" + publicRef + "/document")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray();

        if (!java.util.Arrays.equals(pdf, downloaded)) {
            throw new AssertionError("Downloaded document must match uploaded bytes");
        }
    }

    @Test
    void identityDocument_forbidden_forOtherUser() throws Exception {
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"doc_a","email":"doca@example.com","password":"a very strong passphrase"}
                                """))
                .andExpect(status().isCreated());
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"doc_b","email":"docb@example.com","password":"a very strong passphrase"}
                                """))
                .andExpect(status().isCreated());

        String aLogin = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"identifier":"doca@example.com","password":"a very strong passphrase"}
                                """))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String aToken = objectMapper.readTree(aLogin).get("token").asText();

        String bPublicRef = userRepository.findByEmailIgnoreCase("docb@example.com").orElseThrow().getPublicRef();

        mvc.perform(get("/api/users/" + bPublicRef + "/document")
                        .header("Authorization", "Bearer " + aToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void mfa_challengeAndVerify_returnsJwt() throws Exception {
        capturingSmsGateway.clear();

        User user = userRepository.save(User.builder()
                .username("mfa_1")
                .email("mfa1@example.com")
                .phoneNumber("+15550000001")
                .passwordHash(passwordEncoder.encode("a very strong passphrase"))
                .role(UserRole.USER)
                .status(AccountStatus.ACTIVE)
                .failedLoginAttempts(0)
                .lockoutUntil(null)
                .build());

        mvc.perform(post("/api/auth/mfa/challenge")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"identifier":"mfa1@example.com","password":"a very strong passphrase"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CHALLENGE_SENT"));

        String code = capturingSmsGateway.requireCode();

        String verifyBody = mvc.perform(post("/api/auth/mfa/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"identifier":"mfa1@example.com","code":"%s"}
                                """.formatted(code)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("VERIFIED"))
                .andExpect(jsonPath("$.token").isString())
                .andReturn().getResponse().getContentAsString();

        String jwt = objectMapper.readTree(verifyBody).get("token").asText();
        if (jwt.isBlank()) {
            throw new AssertionError("Expected JWT from MFA verify");
        }
    }

    @Test
    void apiKeys_issueListRevoke() throws Exception {
        mvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"ak_1","email":"ak1@example.com","password":"a very strong passphrase"}
                                """))
                .andExpect(status().isCreated());

        String login = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"identifier":"ak1@example.com","password":"a very strong passphrase"}
                                """))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String token = objectMapper.readTree(login).get("token").asText();

        String issue = mvc.perform(post("/api/auth/api-keys")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name":"integration-1"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.apiKey").isString())
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andReturn().getResponse().getContentAsString();

        long id = objectMapper.readTree(issue).get("id").asLong();

        mvc.perform(get("/api/auth/api-keys")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(id))
                .andExpect(jsonPath("$[0].status").value("ACTIVE"));

        mvc.perform(delete("/api/auth/api-keys/" + id)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REVOKED"));
    }

    @Test
    void adminDirectoryLookup_requiresAdmin_andReturnsJson() throws Exception {
        // mock results
        org.mockito.Mockito.when(directoryService.searchUser("example.com", "alice"))
                .thenReturn(java.util.List.of(new DirectoryUserResponse("alice", "Alice", "alice@example.com", "uid=alice,dc=example,dc=com")));

        userRepository.save(User.builder()
                .username("dir_admin")
                .email("diradmin@example.com")
                .passwordHash(passwordEncoder.encode("admin strong passphrase"))
                .role(UserRole.ADMIN)
                .status(AccountStatus.ACTIVE)
                .failedLoginAttempts(0)
                .lockoutUntil(null)
                .build());

        String adminLoginBody = mvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"identifier":"diradmin@example.com","password":"admin strong passphrase"}
                                """))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String adminToken = objectMapper.readTree(adminLoginBody).get("token").asText();

        mvc.perform(get("/api/admin/directory/user-search?dc=example.com&username=alice")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].uid").value("alice"));
    }

    @TestConfiguration
    static class ResetTestConfig {
        @Bean
        @Primary
        CapturingResetSender capturingResetSender() {
            return new CapturingResetSender();
        }
    }

    static final class CapturingResetSender implements PasswordResetNotificationSender {
        private final AtomicReference<String> lastToken = new AtomicReference<>();

        @Override
        public void sendResetToken(UserAccountSnapshot account, String resetToken) {
            // SECURITY: [Layer 6] Tests capture token without logging.
            lastToken.set(resetToken);
        }

        void clear() {
            lastToken.set(null);
        }

        String requireToken() {
            String token = lastToken.get();
            if (token == null || token.isBlank()) {
                throw new AssertionError("Expected reset token to be delivered out-of-band for existing user");
            }
            return token;
        }
    }

    @TestConfiguration
    static class SmsTestConfig {
        @Bean
        @Primary
        CapturingSmsGateway capturingSmsGateway() {
            return new CapturingSmsGateway();
        }
    }

    static final class CapturingSmsGateway implements SmsGateway {
        private static final Pattern CODE = Pattern.compile("\\b([0-9]{6})\\b");
        private final AtomicReference<String> lastMessage = new AtomicReference<>();

        @Override
        public void sendOtp(String phoneNumber, String message) {
            // SECURITY: [Layer 6] Capture without logging.
            lastMessage.set(message);
        }

        void clear() {
            lastMessage.set(null);
        }

        String requireCode() {
            String msg = lastMessage.get();
            if (msg == null) {
                throw new AssertionError("Expected OTP message to be sent");
            }
            Matcher m = CODE.matcher(msg);
            if (!m.find()) {
                throw new AssertionError("Expected 6-digit code in message");
            }
            return m.group(1);
        }
    }
}

