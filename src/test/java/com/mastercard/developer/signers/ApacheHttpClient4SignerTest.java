package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;
import com.mastercard.developer.oauth.SignatureMethod;
import com.mastercard.developer.test.TestUtils;
import org.apache.http.Header;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.junit.Assert;
import org.junit.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.net.URI;
import java.nio.charset.Charset;
import java.security.PrivateKey;

import static com.mastercard.developer.test.TestUtils.UTF8_CHARSET;

public class ApacheHttpClient4SignerTest {

    @Test
    public void testSign_ShouldAddOAuth1HeaderToPostRequest() throws Exception {

        // GIVEN
        PrivateKey signingKey = TestUtils.getTestSigningKey();
        String consumerKey = "Some key";
        HttpPost httpPost = new HttpPost("https://api.mastercard.com/service");
        httpPost.setEntity(new StringEntity( "{\"foo\":\"bår\"}", ContentType.APPLICATION_JSON)); // ContentType.APPLICATION_JSON implies UTF-8 encoding

        // WHEN
        ApacheHttpClient4Signer instanceUnderTest = new ApacheHttpClient4Signer(consumerKey, signingKey);
        instanceUnderTest.sign(httpPost);

        // THEN
        Header[] authorizationHeaders = httpPost.getHeaders("Authorization");
        String authorizationHeaderValue = authorizationHeaders[0].getValue();
        Assert.assertNotNull(authorizationHeaderValue);
    }

    @ParameterizedTest
    @EnumSource(SignatureMethod.class)
    public void testSign_ShouldInvokeSigningAsExpected(SignatureMethod signatureMethod) throws Exception {

        // GIVEN
        PrivateKey signingKey = TestUtils.getTestSigningKey();
        String consumerKey = "Some key";
        Charset charset = UTF8_CHARSET;
        String payload = "{\"foo\":\"bar\"}";

        HttpPost httpPost = new HttpPost("https://api.mastercard.com/service");
        httpPost.setEntity(new StringEntity(payload, ContentType.APPLICATION_JSON)); // default UTF-8

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

            ApacheHttpClient4Signer instanceUnderTest = new ApacheHttpClient4Signer(consumerKey, signingKey, signatureMethod);

            // WHEN
            instanceUnderTest.sign(httpPost);

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
