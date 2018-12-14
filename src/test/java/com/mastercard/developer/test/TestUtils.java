package com.mastercard.developer.test;

import java.nio.charset.Charset;
import java.security.PrivateKey;

import static com.mastercard.developer.utils.SecurityUtils.loadPrivateKey;

public class TestUtils {

    public static final Charset UTF8_CHARSET = Charset.forName("UTF-8");

    public static PrivateKey getTestPrivateKey() throws Exception {
        return loadPrivateKey("./src/test/resources/test_key_container.p12", "mykeyalias", "Password1");
    }
}
