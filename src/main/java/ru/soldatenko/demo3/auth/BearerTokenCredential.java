package ru.soldatenko.demo3.auth;

import lombok.Data;

import javax.security.enterprise.credential.Credential;

@Data
public class BearerTokenCredential implements Credential {
    private String token;

    public BearerTokenCredential(String token) {
        this.token = (token.startsWith("Bearer ") ? token.substring("Bearer ".length()) : token);
    }
}
