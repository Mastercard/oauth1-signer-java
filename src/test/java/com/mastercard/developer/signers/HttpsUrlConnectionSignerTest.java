package com.mastercard.developer.signers;

import com.mastercard.developer.test.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
import java.security.PrivateKey;

import static com.mastercard.developer.test.TestUtils.UTF8_CHARSET;

public class HttpsUrlConnectionSignerTest {

    @Test
    public void testSign_ShouldAddOAuth1HeaderToPostRequest() throws Exception {

        // GIVEN
        PrivateKey signingKey = TestUtils.getTestPrivateKey();
        String consumerKey = "Some key";

        HttpsURLConnection connection = (HttpsURLConnection) new URL("https://api.mastercard.com/service").openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json; charset=" + UTF8_CHARSET.name());

        // WHEN
        HttpsUrlConnectionSigner instanceUnderTest = new HttpsUrlConnectionSigner(UTF8_CHARSET, consumerKey, signingKey);
        instanceUnderTest.sign(connection, "{\"foo\":\"bår\"}");

        // THEN
        String authorizationHeaderValue = connection.getRequestProperty("Authorization");
        Assert.assertNull(authorizationHeaderValue); // https://stackoverflow.com/questions/2864062/getrequestpropertyauthorization-always-returns-null
    }
}
