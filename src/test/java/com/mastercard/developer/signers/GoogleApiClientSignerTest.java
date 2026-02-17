package com.mastercard.developer.signers;

import com.google.api.client.http.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.mastercard.developer.oauth.OAuth;
import com.mastercard.developer.oauth.SignatureMethod;
import com.mastercard.developer.test.TestUtils;
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

public class GoogleApiClientSignerTest {

    @Test
    public void testSign_ShouldAddOAuth1HeaderToPostRequest() throws Exception {

        // GIVEN
        PrivateKey signingKey = TestUtils.getTestSigningKey();
        String consumerKey = "Some key";
        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        HttpContent httpContent = new ByteArrayContent("application/json; charset=" + UTF8_CHARSET.name(), "{\"foo\":\"bår\"}".getBytes());
        HttpRequest request = requestFactory.buildPostRequest(new GenericUrl("https://api.mastercard.com/service"), httpContent);
        request.setRequestMethod("POST");

        // WHEN
        GoogleApiClientSigner instanceUnderTest = new GoogleApiClientSigner(consumerKey, signingKey);
        instanceUnderTest.sign(request);

        // THEN
        String authorizationHeaderValue = request.getHeaders().getAuthorization();
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

        HttpRequestFactory requestFactory = new NetHttpTransport().createRequestFactory();
        HttpContent httpContent = new ByteArrayContent("application/json; charset=" + charset.name(), payload.getBytes(charset));
        HttpRequest request = requestFactory.buildPostRequest(new GenericUrl("https://api.mastercard.com/service"), httpContent);
        request.setRequestMethod("POST");

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

            GoogleApiClientSigner instanceUnderTest = new GoogleApiClientSigner(charset, consumerKey, signingKey, signatureMethod);

            // WHEN
            instanceUnderTest.sign(request);

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
