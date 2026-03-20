package com.um.springbootprojstructure.admin.directory;

import javax.naming.Name;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.ldap.support.LdapNameBuilder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@ConditionalOnProperty(prefix = "security.directory", name = "enabled", havingValue = "true")
@ConditionalOnBean(LdapTemplate.class)
public class DirectoryService implements DirectoryLookupService {
    private final LdapTemplate ldapTemplate;

    public DirectoryService(LdapTemplate ldapTemplate) {
        this.ldapTemplate = ldapTemplate;
    }

    @Override
    public List<DirectoryUserResponse> searchUser(String domain, String username) {
        Name base = baseDn(domain);

        // SECURITY: [Layer 3] Spring LDAP builder escapes filter values to prevent LDAP injection.
        LdapQuery query = LdapQueryBuilder.query()
                .base(base)
                .attributes("uid", "cn", "mail")
                .where("uid").is(username);

        return ldapTemplate.search(query, (ContextMapper<DirectoryUserResponse>) ctx -> map(ctx));
    }

    private static DirectoryUserResponse map(Object ctx) throws javax.naming.NamingException {
        DirContextAdapter adapter = (DirContextAdapter) ctx;
        Attributes attrs = adapter.getAttributes();
        String uid = stringAttr(attrs, "uid");
        String cn = stringAttr(attrs, "cn");
        String mail = stringAttr(attrs, "mail");
        String dn = adapter.getNameInNamespace();
        // SECURITY: [Layer 6] Return minimal attributes; avoid returning full LDAP object / sensitive attributes.
        return new DirectoryUserResponse(uid, cn, mail, dn);
    }

    private static String stringAttr(Attributes attrs, String name) throws javax.naming.NamingException {
        if (attrs == null || attrs.get(name) == null || attrs.get(name).get() == null) {
            return null;
        }
        return String.valueOf(attrs.get(name).get());
    }

    public static LdapName baseDn(String domain) {
        // SECURITY: [Layer 6] Construct base DN from validated dot-separated domain components.
        String[] parts = domain.split("\\.");
        LdapNameBuilder b = LdapNameBuilder.newInstance();
        for (String p : parts) {
            b.add("dc", p);
        }
        return (LdapName) b.build();
    }
}

