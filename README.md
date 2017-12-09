# demo-jsr375-web

This is demo implementation of JSR-375 HttpAuthenticationMechanism supporting Http sessions and 4 authentication methods

* Form based authentication
* Basic authentication
* Client Certificate authentication
* Bearer token authentication

This application should be deployed on JavaEE 8 compatible application server.

Thos System Properties should be set to make this application work.

```
demo3.ldap.url           = ldaps://demo3.soldatenko.ru:636
demo3.ldap.user.base.dn  = ou=Users,dc=demo3,dc=soldatenko,dc=ru
demo3.ldap.group.base.dn = ou=Groups,dc=demo3,dc=soldatenko,dc=ru
demo3.ldap.x509.base.dn  = ou=x509,dc=demo3,dc=soldatenko,dc=ru
demo3.ldap.token.base.dn = ou=Tokens,dc=demo3,dc=soldatenko,dc=ru

demo3.ldap.service.dn       = service-login-name
demo3.ldap.service.password = change-me
```