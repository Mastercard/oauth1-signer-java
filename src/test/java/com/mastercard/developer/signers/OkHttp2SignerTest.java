package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;
import com.mastercard.developer.oauth.SignatureMethod;
import com.squareup.okhttp.*;
import com.squareup.okhttp.Request.Builder;
import org.junit.Assert;
import org.junit.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;

import static com.mastercard.developer.test.TestUtils.UTF8_CHARSET;
import static com.mastercard.developer.test.TestUtils.getTestSigningKey;

public class OkHttp2SignerTest {

    @ParameterizedTest
    @EnumSource(SignatureMethod.class)
    public void testConstructor_WithSignatureMethod_ShouldUseUtf8CharsetAndProvidedSignatureMethod(SignatureMethod signatureMethod) throws Exception {

        PrivateKey signingKey = getTestSigningKey();
        String consumerKey = "Some key";

        OkHttp2Signer instanceUnderTest = new OkHttp2Signer(consumerKey, signingKey, signatureMethod);

        Assert.assertEquals(consumerKey, instanceUnderTest.consumerKey);
        Assert.assertEquals(signingKey, instanceUnderTest.signingKey);
        Assert.assertEquals(StandardCharsets.UTF_8, instanceUnderTest.charset);
        Assert.assertEquals(signatureMethod, instanceUnderTest.signatureMethod);
    }

    @Test
    public void testConstructor_WithCharset_ShouldUseProvidedCharsetAndDefaultSignatureMethod() throws Exception {

        PrivateKey signingKey = getTestSigningKey();
        String consumerKey = "Some key";
        Charset charset = UTF8_CHARSET;

        OkHttp2Signer instanceUnderTest = new OkHttp2Signer(charset, consumerKey, signingKey);

        Assert.assertEquals(consumerKey, instanceUnderTest.consumerKey);
        Assert.assertEquals(signingKey, instanceUnderTest.signingKey);
        Assert.assertEquals(charset, instanceUnderTest.charset);
        Assert.assertEquals(OAuth.DEFAULT_SIGNATURE_METHOD, instanceUnderTest.signatureMethod);
    }

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
        OkHttp2Signer instanceUnderTest = new OkHttp2Signer(consumerKey, signingKey);
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

            OkHttp2Signer instanceUnderTest = new OkHttp2Signer(charset, consumerKey, signingKey, signatureMethod);

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
