package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;
import com.mastercard.developer.oauth.SignatureMethod;
import com.mastercard.developer.test.TestUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
import java.net.URI;
import java.security.PrivateKey;
import java.nio.charset.Charset;

import static com.mastercard.developer.test.TestUtils.UTF8_CHARSET;

public class HttpsUrlConnectionSignerTest {

    @Test
    public void testSign_ShouldAddOAuth1HeaderToPostRequest() throws Exception {

        // GIVEN
        PrivateKey signingKey = TestUtils.getTestSigningKey();
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

    @ParameterizedTest
    @EnumSource(SignatureMethod.class)
    public void testSign_ShouldInvokeSigningAsExpected(SignatureMethod signatureMethod) throws Exception {

        // GIVEN
        PrivateKey signingKey = TestUtils.getTestSigningKey();
        String consumerKey = "Some key";
        Charset charset = UTF8_CHARSET;
        String payload = "{\"foo\":\"bar\"}";

        URL url = new URL("https://api.mastercard.com/service");
        HttpsURLConnection connection = Mockito.mock(HttpsURLConnection.class);
        Mockito.when(connection.getURL()).thenReturn(url);
        Mockito.when(connection.getRequestMethod()).thenReturn("POST");

        URI expectedUri = URI.create("https://api.mastercard.com/service");

        try (MockedStatic<OAuth> oauthMock = Mockito.mockStatic(OAuth.class)) {
            oauthMock.when(() -> OAuth.getAuthorizationHeader(
                    expectedUri,
                    "POST",
                    payload,
                    charset,
                    consumerKey,
                    signingKey,
                    signatureMethod
            )).thenReturn("OAuth header");

            HttpsUrlConnectionSigner instanceUnderTest = new HttpsUrlConnectionSigner(charset, consumerKey, signingKey, signatureMethod);

            // WHEN
            instanceUnderTest.sign(connection, payload);

            // THEN
            oauthMock.verify(() -> OAuth.getAuthorizationHeader(
                    expectedUri,
                    "POST",
                    payload,
                    charset,
                    consumerKey,
                    signingKey,
                    signatureMethod
            ));
        }
    }
}
