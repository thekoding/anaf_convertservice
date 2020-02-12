package com.kodingtech;

import java.security.cert.X509Certificate;

public class CertAlias {
    public String _alias;
    public X509Certificate _cert;

    public CertAlias(String alias, X509Certificate cert) {
        _alias = alias;
        _cert = cert;
    }

    @Override
    public String toString() {
        return _alias;// + _cert.getIssuerDN().getName();
    }
}