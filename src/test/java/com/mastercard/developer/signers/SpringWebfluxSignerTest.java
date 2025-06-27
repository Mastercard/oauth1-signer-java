package com.mastercard.developer.signers;

import com.squareup.okhttp.MediaType;
import com.squareup.okhttp.RequestBody;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.ReactiveHttpOutputMessage;
import org.springframework.web.reactive.function.BodyInserter;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientRequest;

import java.net.URI;
import java.security.PrivateKey;

import static com.mastercard.developer.test.TestUtils.UTF8_CHARSET;
import static com.mastercard.developer.test.TestUtils.getTestSigningKey;

public class SpringWebfluxSignerTest {

    @Test
    public void testSign_ShouldAddOAuth1HeaderToPostRequest() throws Exception {

        // GIVEN
        PrivateKey signingKey = getTestSigningKey();
        String consumerKey = "Some key";
        MediaType jsonMediaType = MediaType.parse("application/json; charset=" + UTF8_CHARSET.name());
        RequestBody body = RequestBody.create(jsonMediaType, "{\"foo\":\"bår\"}");
        BodyInserter<RequestBody, ReactiveHttpOutputMessage> inserter = BodyInserters.fromValue(body);
        ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://api.mastercard.com/service")).body(inserter).build();

        // WHEN
        SpringWebfluxSigner instanceUnderTest = new SpringWebfluxSigner(consumerKey, signingKey);
        ClientRequest signedRequest = instanceUnderTest.sign(request);

        // THEN
        String authorizationHeaderValue = signedRequest.headers().getFirst("Authorization");
        Assert.assertNotNull(authorizationHeaderValue);
    }
}