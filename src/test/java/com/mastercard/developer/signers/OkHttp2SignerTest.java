package com.mastercard.developer.signers;

import com.squareup.okhttp.*;
import com.squareup.okhttp.Request.Builder;
import org.junit.Assert;
import org.junit.Test;

import java.security.PrivateKey;

import static com.mastercard.developer.test.TestUtils.UTF8_CHARSET;
import static com.mastercard.developer.test.TestUtils.getTestPrivateKey;

public class OkHttp2SignerTest {

    @Test
    public void testSign_ShouldAddOAuth1HeaderToRequest_WhenValidInputs() throws Exception {

        // GIVEN
        PrivateKey signingKey = getTestPrivateKey();
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
}
