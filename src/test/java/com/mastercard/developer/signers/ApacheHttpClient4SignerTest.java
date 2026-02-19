package com.mastercard.developer.signers;

import com.mastercard.developer.test.TestUtils;
import org.apache.http.Header;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.junit.Assert;
import org.junit.Test;

import java.security.PrivateKey;

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
}
