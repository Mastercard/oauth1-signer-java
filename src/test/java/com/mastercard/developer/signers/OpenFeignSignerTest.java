package com.mastercard.developer.signers;

import feign.RequestTemplate;
import org.junit.Assert;
import org.junit.Test;

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
}
