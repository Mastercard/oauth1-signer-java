package com.mastercard.developer.utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * Utility class.
 */
public final class AuthenticationUtils {

    private AuthenticationUtils() {
    }

    /**
     * Load a RSA signing key out of a PKCS#12 container.
     */
    public static PrivateKey loadSigningKey(String pkcs12KeyFilePath,
                                            String signingKeyAlias,
                                            String signingKeyPassword) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        KeyStore pkcs12KeyStore = KeyStore.getInstance("PKCS12");
        pkcs12KeyStore.load(new FileInputStream(pkcs12KeyFilePath), signingKeyPassword.toCharArray());
        return (PrivateKey) pkcs12KeyStore.getKey(signingKeyAlias, signingKeyPassword.toCharArray());
    }
}
