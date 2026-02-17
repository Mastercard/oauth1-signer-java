package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;
import com.mastercard.developer.oauth.SignatureMethod;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
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
import static com.mastercard.developer.test.TestUtils.getTestSigningKey;
import static okhttp3.Request.Builder;

public class OkHttpSignerTest {

    @Test
    public void testSign_ShouldAddOAuth1HeaderToPostRequest() throws Exception {

        // GIVEN
        PrivateKey signingKey = getTestSigningKey();
        String consumerKey = "Some key";
        MediaType jsonMediaType = MediaType.parse("application/json; charset=" + UTF8_CHARSET.name());
        RequestBody body = RequestBody.create(jsonMediaType, "{\"foo\":\"bår\"}");
        Builder requestBuilder = new Builder()
                .url("https://api.mastercard.com/service")
                .post(body);

        // WHEN
        OkHttpSigner instanceUnderTest = new OkHttpSigner(consumerKey, signingKey);
        instanceUnderTest.sign(requestBuilder);

        // THEN
        Request request = requestBuilder.build();
        String authorizationHeaderValue = request.header("Authorization");
        Assert.assertNotNull(authorizationHeaderValue);
    }

    @ParameterizedTest
    @EnumSource(SignatureMethod.class)
    public void testSign_ShouldInvokeSigningAsExpected(SignatureMethod signatureMethod) throws Exception {

        // GIVEN
        PrivateKey signingKey = getTestSigningKey();
        String consumerKey = "Some key";
        Charset charset = UTF8_CHARSET;
        String payload = "{\"foo\":\"bar\"}";
        MediaType jsonMediaType = MediaType.parse("application/json; charset=" + charset.name());
        RequestBody body = RequestBody.create(jsonMediaType, payload);
        Builder requestBuilder = new Builder()
                .url("https://api.mastercard.com/service")
                .post(body);

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

            OkHttpSigner instanceUnderTest = new OkHttpSigner(charset, consumerKey, signingKey, signatureMethod);

            // WHEN
            instanceUnderTest.sign(requestBuilder);

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
