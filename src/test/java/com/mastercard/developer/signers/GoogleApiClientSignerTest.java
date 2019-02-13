package com.mastercard.developer.signers;

import com.google.api.client.http.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.mastercard.developer.test.TestUtils;
import org.junit.Assert;
import org.junit.Test;

import java.security.PrivateKey;

import static com.mastercard.developer.test.TestUtils.UTF8_CHARSET;

public class GoogleApiClientSignerTest {

    @Test
    public void testSign_ShouldAddOAuth1HeaderToPostRequest() throws Exception {

        // GIVEN
        PrivateKey signingKey = TestUtils.getTestPrivateKey();
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
}
