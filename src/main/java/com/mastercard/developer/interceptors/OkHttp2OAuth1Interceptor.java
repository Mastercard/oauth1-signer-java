package com.mastercard.developer.interceptors;

import com.mastercard.developer.signers.OkHttp2Signer;
import com.squareup.okhttp.*;

import java.io.IOException;
import java.security.PrivateKey;

/**
 * An OkHttp2 interceptor for computing and adding an OAuth1 authorization header to HTTP requests.
 */
public class OkHttp2OAuth1Interceptor implements Interceptor {

    private final OkHttp2Signer signer;

    public OkHttp2OAuth1Interceptor(String consumerKey, PrivateKey signingKey) {
        this.signer = new OkHttp2Signer(consumerKey, signingKey);
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request.Builder builder = chain.request().newBuilder();
        signer.sign(builder);
        return chain.proceed(builder.build());
    }
}
