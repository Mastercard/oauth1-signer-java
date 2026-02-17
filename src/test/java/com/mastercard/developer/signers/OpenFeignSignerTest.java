package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;
import com.mastercard.developer.oauth.SignatureMethod;
import feign.RequestTemplate;
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
import java.util.Collection;

import static com.mastercard.developer.test.TestUtils.getTestSigningKey;

public class OpenFeignSignerTest {

    @Test
    public void testSign_ShouldAddOAuth1HeaderToPostRequest() throws Exception {

        // GIVEN
        PrivateKey signingKey = getTestSigningKey();
        String consumerKey = "Some key";
        RequestTemplate requestTemplate = new RequestTemplate();
        requestTemplate.method("POST");
        requestTemplate.append("/service");
        requestTemplate.body("{\"foo\":\"bår\"}");

        // WHEN
        OpenFeignSigner instanceUnderTest = new OpenFeignSigner(StandardCharsets.UTF_8,
                consumerKey,
                signingKey,
                "https://api.mastercard.com/");
        instanceUnderTest.sign(requestTemplate);

        // THEN
        Collection<String> authorizationHeaders = requestTemplate.headers().get("Authorization");
        String authorizationHeaderValue = (String)authorizationHeaders.toArray()[0];
        Assert.assertNotNull(authorizationHeaderValue);
    }

    @Test
    public void testSign_ShouldAddOAuth1HeaderToGetRequest() throws Exception {

        // GIVEN
        PrivateKey signingKey = getTestSigningKey();
        String consumerKey = "Some key";
        RequestTemplate requestTemplate = new RequestTemplate();
        requestTemplate.method("GET");
        requestTemplate.append("/service");

        // WHEN
        OpenFeignSigner instanceUnderTest = new OpenFeignSigner(consumerKey, signingKey, "https://api.mastercard.com/");
        instanceUnderTest.sign(requestTemplate);

        // THEN
        Collection<String> authorizationHeaders = requestTemplate.headers().get("Authorization");
        String authorizationHeaderValue = (String)authorizationHeaders.toArray()[0];
        Assert.assertNotNull(authorizationHeaderValue);
    }

    @ParameterizedTest
    @EnumSource(SignatureMethod.class)
    public void testSign_ShouldInvokeSigningAsExpected(SignatureMethod signatureMethod) throws Exception {

        // GIVEN
        PrivateKey signingKey = getTestSigningKey();
        String consumerKey = "Some key";
        Charset charset = StandardCharsets.UTF_8;
        String baseUri = "https://api.mastercard.com/";
        RequestTemplate requestTemplate = new RequestTemplate();
        requestTemplate.method("POST");
        requestTemplate.append("/service");
        String payload = "{\"foo\":\"bar\"}";
        requestTemplate.body(payload);

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

            OpenFeignSigner instanceUnderTest = new OpenFeignSigner(charset,
                    consumerKey,
                    signingKey,
                    baseUri,
                    signatureMethod);

            // WHEN
            instanceUnderTest.sign(requestTemplate);

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
