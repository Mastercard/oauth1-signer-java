package com.mastercard.developer.signers;

import feign.RequestTemplate;
import org.junit.Assert;
import org.junit.Test;

import java.security.PrivateKey;
import java.util.Collection;

import static com.mastercard.developer.test.TestUtils.getTestPrivateKey;

public class OpenFeignSignerTest {

    @Test
    public void testSign_ShouldAddOAuth1HeaderToRequest_WhenValidInputs() throws Exception {

        // GIVEN
        PrivateKey signingKey = getTestPrivateKey();
        String consumerKey = "Some key";
        RequestTemplate requestTemplate = new RequestTemplate();
        requestTemplate.method("POST");
        requestTemplate.append("/service");
        requestTemplate.body("{\"foo\":\"bår\"}");

        // WHEN
        OpenFeignSigner instanceUnderTest = new OpenFeignSigner(consumerKey, signingKey, "https://api.mastercard.com/");
        instanceUnderTest.sign(requestTemplate);

        // THEN
        Collection<String> authorizationHeaders = requestTemplate.headers().get("Authorization");
        String authorizationHeaderValue = (String)authorizationHeaders.toArray()[0];
        Assert.assertNotNull(authorizationHeaderValue);
    }
}
