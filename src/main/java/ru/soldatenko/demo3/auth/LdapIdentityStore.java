package ru.soldatenko.demo3.auth;

import lombok.Cleanup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.json.bind.JsonbBuilder;
import javax.json.bind.JsonbException;
import javax.naming.AuthenticationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.enterprise.credential.CallerOnlyCredential;
import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.credential.UsernamePasswordCredential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static java.time.LocalDateTime.now;
import static javax.naming.Context.*;
import static javax.security.enterprise.identitystore.CredentialValidationResult.NOT_VALIDATED_RESULT;

public class LdapIdentityStore implements IdentityStore {
    public static final int MAX_GROUPS_PER_USER = 100_000;
    Logger log = LoggerFactory.getLogger(LdapIdentityStore.class);

    @Override
    public CredentialValidationResult validate(Credential credential) {
        try {
            if (credential instanceof UsernamePasswordCredential) {
                return validate((UsernamePasswordCredential) credential);
            } else if (credential instanceof CallerOnlyCredential) {
                return validate((CallerOnlyCredential) credential);
            } else if (credential instanceof CertificateCredentials) {
                return validate((CertificateCredentials) credential);
            } else if (credential instanceof BearerTokenCredential) {
                return validate((BearerTokenCredential) credential);
            } else {
                return NOT_VALIDATED_RESULT;
            }
        } catch (AuthenticationException e) {
            return CredentialValidationResult.INVALID_RESULT;
        } catch (RuntimeException e) {
            log.error("LDAP access error", e);
            throw e;
        } catch (Exception e) {
            log.error("LDAP access error", e);
            throw new IllegalStateException(e);
        }
    }

    public CredentialValidationResult validate(UsernamePasswordCredential credential) throws Exception {
        String userBaseDn = System.getProperty("demo3.ldap.user.base.dn");
        LdapName userDn = (LdapName) new LdapName(userBaseDn).add(new Rdn("uid", credential.getCaller()));
        @Cleanup
        InitialLdapContext ldap = openUserLdapContext(userDn.toString(), credential.getPasswordAsString());
        Demo3Principal principal = Demo3Principal.builder()
                .userDn(userDn)
                .groups(readGroups(ldap, userDn))
                .build();
        return new CredentialValidationResult(null, principal, userDn.toString(), null, principal.getGroupNames());
    }

    public CredentialValidationResult validate(CallerOnlyCredential credential) throws Exception {
        @Cleanup
        InitialLdapContext ldap = openLdapContext();
        LdapName userDn = readUser(ldap, credential.getCaller());
        Demo3Principal principal = Demo3Principal.builder()
                .userDn(userDn)
                .groups(readGroups(ldap, userDn))
                .build();
        return new CredentialValidationResult(null, principal, userDn.toString(), null, principal.getGroupNames());
    }

    public CredentialValidationResult validate(CertificateCredentials credential) throws Exception {
        @Cleanup
        InitialLdapContext ldap = openLdapContext();
        String userRef = findUser(ldap, credential.getCertificate());
        LdapName userDn = readUser(ldap, userRef);
        Demo3Principal principal = Demo3Principal.builder()
                .userDn(userDn)
                .groups(readGroups(ldap, userDn))
                .build();
        return new CredentialValidationResult(null, principal, userDn.toString(), null, principal.getGroupNames());
    }

    public CredentialValidationResult validate(BearerTokenCredential credential) throws Exception {
        @Cleanup
        InitialLdapContext ldap = openLdapContext();
        TokenInfo tokenInfo = findToken(ldap, credential.getToken());
        LdapName userDn = readUser(ldap, tokenInfo.getUserDn());
        Demo3Principal principal = Demo3Principal.builder()
                .userDn(userDn)
                .groups(readGroups(ldap, userDn))
                .build();
        return new CredentialValidationResult(null, principal, userDn.toString(), null, principal.getGroupNames());
    }

    private InitialLdapContext openUserLdapContext(String bindDn, String bindCredential) throws NamingException {
        Hashtable<String, String> environment = new Hashtable<>();
        environment.put(INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        environment.put(PROVIDER_URL, System.getProperty("demo3.ldap.url"));
        environment.put(SECURITY_AUTHENTICATION, "simple");
        environment.put(SECURITY_PRINCIPAL, bindDn);
        environment.put(SECURITY_CREDENTIALS, bindCredential);
        environment.put("com.sun.jndi.ldap.connect.timeout", "500");
        environment.put("com.sun.jndi.ldap.read.timeout", "1000");
        environment.put("java.naming.ldap.derefAliases", "never");

        return new InitialLdapContext(environment, null);
    }

    private InitialLdapContext openLdapContext() throws NamingException {
        return openUserLdapContext(
                System.getProperty("demo3.ldap.service.dn"),
                System.getProperty("demo3.ldap.service.password")
        );
    }

    private Set<LdapName> readGroups(InitialLdapContext ldap, LdapName member) throws NamingException {
        LdapName groupsDn = new LdapName(System.getProperty("demo3.ldap.group.base.dn"));
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.ONELEVEL_SCOPE);
        controls.setCountLimit(MAX_GROUPS_PER_USER);
        controls.setDerefLinkFlag(false);
        controls.setReturningAttributes(new String[0]);
        ArrayList<LdapName> membersToQuery = new ArrayList<>();
        membersToQuery.add(member);
        LinkedHashSet<LdapName> groups = new LinkedHashSet<>();
        while (membersToQuery.size() > 0) {
            String query = "(&(objectClass=groupOfNames)(|" +
                    IntStream.range(0, membersToQuery.size())
                            .mapToObj(i -> "(member={" + i + "})")
                            .collect(Collectors.joining()) +
                    "))";
            @Cleanup
            NamingEnumeration<SearchResult> result = ldap.search(groupsDn, query, membersToQuery.toArray(), controls);
            membersToQuery.clear();
            while (result.hasMore()) {
                SearchResult r = result.next();
                LdapName group = new LdapName(r.getNameInNamespace());
                boolean isAdded = groups.add(group);
                if (isAdded) {
                    membersToQuery.add(group);
                }
            }
            if (groups.size() >= MAX_GROUPS_PER_USER) {
                log.warn("User {} have too many groups {}, not all groups may be loaded.", member, groups.size());
                break;
            }
        }
        return groups;
    }

    private LdapName readUser(InitialLdapContext ldap, String userDn) throws NamingException {
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.OBJECT_SCOPE);
        controls.setReturningAttributes(new String[0]);

        // todo put Enabled filter into query or into returning attributes
        @Cleanup
        NamingEnumeration<SearchResult> result = ldap.search(userDn, "(objectClass=inetOrgPerson)", controls);
        if (result.hasMore()) {
            SearchResult user = result.next();
            return new LdapName(user.getNameInNamespace());
        }
        throw new AuthenticationException("User [" + userDn + "] is not allowed to login.");
    }

    private String findUser(InitialLdapContext ldap, X509Certificate cert) throws NamingException {
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.ONELEVEL_SCOPE);
        controls.setDerefLinkFlag(false);
        controls.setReturningAttributes(new String[]{
                "aliasedObjectName",
                "name"
        });

        @Cleanup
        NamingEnumeration<SearchResult> result = ldap.search(System.getProperty("demo3.ldap.x509.base.dn"),
                "(&(objectClass=alias)(distinguishedName={0}))", new Object[]{cert.getSubjectX500Principal().getName()}, controls);
        if (result.hasMore()) {
            SearchResult alias = result.next();
            Attributes attributes = alias.getAttributes();
            return (String) attributes.get("aliasedObjectName").get();
        }
        throw new AuthenticationException("User for certificate [" + cert.getSubjectX500Principal() + "] is not allowed to login.");
    }

    private TokenInfo findToken(InitialLdapContext ldap, String token) throws Exception {
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.ONELEVEL_SCOPE);
        controls.setDerefLinkFlag(false);
        controls.setReturningAttributes(new String[]{
                "aliasedObjectName",
                "cn",
                "name"
        });
        @Cleanup
        NamingEnumeration<SearchResult> result = ldap.search(System.getProperty("demo3.ldap.token.base.dn"),
                "(&(objectClass=alias)(cn={0}))", new Object[]{token}, controls);
        if (result.hasMore()) {
            SearchResult alias = result.next();
            Attributes attributes = alias.getAttributes();
            Attribute name = attributes.get("name");
            String json = (name != null ? (String) name.get() : "{}");
            try {
                TokenInfo tokenInfo = JsonbBuilder.create().fromJson(json, TokenInfo.class);
                tokenInfo.setUserDn((String) attributes.get("aliasedObjectName").get());
                if (tokenInfo.getExpire() != null) {
                    if (tokenInfo.getExpire().isBefore(now())) {
                        throw new AuthenticationException("Token " + token + " is expired " + tokenInfo.getExpire());
                    }
                }
                return tokenInfo;
            } catch (JsonbException e) {
                log.error("Failed to parse JSON in 'name' attribute of {}", alias.getNameInNamespace(), e);
                throw new AuthenticationException("Can not get token information for " + token + ". " + e.getMessage());
            }
        }
        throw new AuthenticationException("Invalid token " + token + ".");
    }
}
