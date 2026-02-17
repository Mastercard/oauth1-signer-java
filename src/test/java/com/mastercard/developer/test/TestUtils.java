package com.mastercard.developer.test;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.io.IOException;

import static com.mastercard.developer.utils.AuthenticationUtils.loadSigningKey;

public class TestUtils {

    private TestUtils() {
    }

    public static final Charset UTF8_CHARSET = StandardCharsets.UTF_8;
    private static final String TEST_KEYSTORE_PATH = "./src/test/resources/test_key_container.p12";
    private static final String TEST_KEY_ALIAS = "mykeyalias";
    private static final String TEST_KEY_PASSWORD = "Password1";

    public static PrivateKey getTestSigningKey() throws Exception {
        return loadSigningKey(TEST_KEYSTORE_PATH, TEST_KEY_ALIAS, TEST_KEY_PASSWORD);
    }

    public static PublicKey getTestPublicKey() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream keyStream = new FileInputStream(TEST_KEYSTORE_PATH)) {
            keyStore.load(keyStream, TEST_KEY_PASSWORD.toCharArray());
        }
        Certificate certificate = keyStore.getCertificate(TEST_KEY_ALIAS);
        return certificate.getPublicKey();
    }
}
