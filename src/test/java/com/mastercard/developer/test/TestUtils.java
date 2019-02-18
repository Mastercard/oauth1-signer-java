package com.mastercard.developer.test;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;

import static com.mastercard.developer.utils.AuthenticationUtils.loadSigningKey;

public class TestUtils {

    private TestUtils() {
    }

    public static final Charset UTF8_CHARSET = StandardCharsets.UTF_8;

    public static PrivateKey getTestSigningKey() throws Exception {
        return loadSigningKey("./src/test/resources/test_key_container.p12", "mykeyalias", "Password1");
    }
}
