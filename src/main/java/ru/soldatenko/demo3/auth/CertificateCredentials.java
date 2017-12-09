package ru.soldatenko.demo3.auth;

import lombok.Data;

import javax.security.enterprise.credential.Credential;
import java.security.cert.X509Certificate;

@Data
public class CertificateCredentials implements Credential {
    private X509Certificate certificate;

    public CertificateCredentials(X509Certificate cert) {
        this.certificate = cert;
    }
}
