package com.mastercard.developer.interceptors;

import com.mastercard.developer.signers.OkHttpSigner;
import okhttp3.*;

import java.io.IOException;
import java.security.PrivateKey;

/**
 * An OkHttp3 interceptor for computing and adding an OAuth1 authorization header to HTTP requests.
 */
public class OkHttpOAuth1Interceptor implements Interceptor {

    private final OkHttpSigner signer;

    public OkHttpOAuth1Interceptor(String consumerKey, PrivateKey signingKey) {
        this.signer = new OkHttpSigner(consumerKey, signingKey);
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
        Request.Builder builder = chain.request().newBuilder();
        signer.sign(builder);
        return chain.proceed(builder.build());
    }
}
