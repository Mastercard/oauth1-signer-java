package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;
import com.mastercard.developer.oauth.SignatureMethod;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.RequestBody;
import org.junit.Assert;
import org.junit.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;
import org.springframework.http.ReactiveHttpOutputMessage;
import org.springframework.web.reactive.function.BodyInserter;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientRequest;

import java.net.URI;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.util.Map;

import static com.mastercard.developer.test.TestUtils.UTF8_CHARSET;
import static com.mastercard.developer.test.TestUtils.getTestSigningKey;

public class SpringWebfluxSignerTest {

    @Test
    public void testSign_ShouldAddOAuth1HeaderToPostRequest() throws Exception {

        // GIVEN
        PrivateKey signingKey = getTestSigningKey();
        String consumerKey = "Some key";
        BodyInserterWrapper bodyWrapper = new BodyInserterWrapper("{\"foo\":\"bår\"}");
        ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://api.mastercard.com/service")).body(bodyWrapper).build();

        // WHEN
        SpringWebfluxSigner instanceUnderTest = new SpringWebfluxSigner(consumerKey, signingKey);
        ClientRequest signedRequest = instanceUnderTest.sign(request);

        // THEN
        String authorizationHeaderValue = signedRequest.headers().getFirst("Authorization");
        Assert.assertNotNull(authorizationHeaderValue);
    }

    @ParameterizedTest
    @EnumSource(SignatureMethod.class)
    public void testSign_ShouldInvokeSigningAsExpected(SignatureMethod signatureMethod) throws Exception {

        // GIVEN
        PrivateKey signingKey = getTestSigningKey();
        String consumerKey = "Some key";
        Charset charset = UTF8_CHARSET;
        Map<String, String> payload = Map.of("foo", "bar");
        String serializedPayload = new ObjectMapper().writeValueAsString(payload);

        URI expectedUri = URI.create("https://api.mastercard.com/service");
        BodyInserterWrapper bodyWrapper = new BodyInserterWrapper(payload);
        ClientRequest request = ClientRequest.create(HttpMethod.POST, expectedUri).body(bodyWrapper).build();

        try (MockedStatic<OAuth> oauthMock = Mockito.mockStatic(OAuth.class)) {
            oauthMock.when(() -> OAuth.getAuthorizationHeader(
                    expectedUri,
                    "POST",
                    serializedPayload,
                    charset,
                    consumerKey,
                    signingKey,
                    signatureMethod
            )).thenReturn("OAuth header");

            SpringWebfluxSigner instanceUnderTest = new SpringWebfluxSigner(consumerKey, signingKey, signatureMethod);

            // WHEN
            ClientRequest signedRequest = instanceUnderTest.sign(request);

            // THEN
            oauthMock.verify(() -> OAuth.getAuthorizationHeader(
                    expectedUri,
                    "POST",
                    serializedPayload,
                    charset,
                    consumerKey,
                    signingKey,
                    signatureMethod
            ));
        }
    }
}