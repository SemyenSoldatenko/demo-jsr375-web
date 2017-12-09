package ru.soldatenko.demo3.auth;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.json.Json;
import javax.security.enterprise.AuthenticationException;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.security.enterprise.credential.BasicAuthenticationCredential;
import javax.security.enterprise.credential.CallerOnlyCredential;
import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStoreHandler;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.cert.X509Certificate;
import java.util.Optional;

import static javax.security.enterprise.identitystore.CredentialValidationResult.Status.INVALID;
import static javax.security.enterprise.identitystore.CredentialValidationResult.Status.VALID;

@ApplicationScoped
public class MyAuthMechanism implements HttpAuthenticationMechanism {
    public static final String AUTHENTICATED_USER_DN = "AUTHENTICATED_USER_DN";

    @Inject
    IdentityStoreHandler handler;

    @Override
    public AuthenticationStatus validateRequest(HttpServletRequest request, HttpServletResponse response,
                                                HttpMessageContext context) throws AuthenticationException {
        Optional<X509Certificate> clientCertificate = Optional
                .ofNullable((X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate"))
                .filter(array -> array.length > 0)
                .map(array -> array[0]);
        Optional<String> authorization = Optional.ofNullable(request.getHeader("Authorization"));

        CredentialValidationResult validationResult = null;
        if (context.isAuthenticationRequest()) {
            Credential credentials = context.getAuthParameters().getCredential();
            validationResult = handler.validate(credentials);
            if (validationResult.getStatus() == VALID) {
                HttpSession session = request.getSession(true);
                session.setAttribute(AUTHENTICATED_USER_DN, validationResult.getCallerDn());
            }
            return context.notifyContainerAboutLogin(validationResult);
        } else if (request.getSession(false) != null) {
            HttpSession session = request.getSession(true);
            String userDn = (String) session.getAttribute(AUTHENTICATED_USER_DN);
            if (userDn != null) {
                validationResult = handler.validate(new CallerOnlyCredential(userDn));
                if (validationResult.getStatus() == INVALID) {
                    // Previously logged in user was deleted (or disabled) in LDAP
                    // Current request should be performed like there are no http session
                    // TODO what if current request decided to put something in the session?
                    session.invalidate();
                    validationResult = null;
                }
            } else if (clientCertificate.isPresent()) {
                validationResult = handler.validate(new CertificateCredentials(clientCertificate.get()));
                if (validationResult.getStatus() == VALID) {
                    session.setAttribute(AUTHENTICATED_USER_DN, validationResult.getCallerDn());
                }
            }
        } else if (authorization.isPresent() && authorization.get().startsWith("Bearer ")) {
            validationResult = handler.validate(new BearerTokenCredential(authorization.get()));
        } else if (authorization.isPresent() && authorization.get().startsWith("Basic ") && request.isSecure()) {
            validationResult = handler.validate(
                    new BasicAuthenticationCredential(authorization.get().substring("Basic ".length()))
            );
        } else if (clientCertificate.isPresent()) {
            validationResult = handler.validate(new CertificateCredentials(clientCertificate.get()));
        } else if (context.isProtected()) {
            return context.redirect(getLoginPageUrl(request));
        }

        if (validationResult != null) {
            switch (validationResult.getStatus()) {
                case VALID:
                    return context.notifyContainerAboutLogin(validationResult);
                case INVALID:
                    response.setStatus(401);
                    writeJsonError(response, 401, "Authorization failed");
                    return context.notifyContainerAboutLogin(validationResult);
                case NOT_VALIDATED:
                default:
                    // Either configuration error or LDAP outage
                    response.setStatus(503);
                    writeJsonError(response, 503, "No connection to LDAP server");
                    return context.notifyContainerAboutLogin(validationResult);
            }
        }
        return context.doNothing();
    }

    private String getLoginPageUrl(HttpServletRequest request) {
        try {
            return "login_page?go=" + URLEncoder.encode(request.getRequestURI(), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void cleanSubject(HttpServletRequest request, HttpServletResponse response,
                             HttpMessageContext context) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.removeAttribute(AUTHENTICATED_USER_DN);
        }
    }

    private void writeJsonError(HttpServletResponse response, int status, String errorMessage) {
        try {
            Json.createGenerator(response.getOutputStream())
                    .writeStartObject()
                    .writeStartObject("error")
                    .write("httpStatus", status)
                    .write("errorMessage", errorMessage)
                    .writeEnd()
                    .writeEnd()
                    .close();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
