package ru.soldatenko.demo3.auth;

import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;

import javax.naming.ldap.LdapName;
import javax.security.enterprise.CallerPrincipal;
import java.util.Set;
import java.util.stream.Collectors;

@EqualsAndHashCode(callSuper = false)
@Data
@Builder
public class Demo3Principal extends CallerPrincipal {
    private LdapName userDn;
    private Set<LdapName> groups;

    public Demo3Principal(LdapName userDn, Set<LdapName> groups) {
        super(userDn.toString());
        this.userDn = userDn;
        this.groups = groups;
    }

    public Set<String> getGroupNames() {
        Set<String> result = groups.stream()
                .map(LdapName::toString)
                .collect(Collectors.toSet());
        result.add(userDn.toString());
        return result;
    }
}
