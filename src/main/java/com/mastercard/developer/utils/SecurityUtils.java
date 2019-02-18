package com.mastercard.developer.utils;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * Utility class.
 * @deprecated Use {@link com.mastercard.developer.utils.AuthenticationUtils} instead.
 */
@Deprecated
public final class SecurityUtils {

    private SecurityUtils() {
    }

    @Deprecated
    public static PrivateKey loadPrivateKey(String pkcs12KeyFilePath,
                                            String keyAlias,
                                            String keyPassword) throws IOException, NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return AuthenticationUtils.loadSigningKey(pkcs12KeyFilePath, keyAlias, keyPassword);
    }
}
