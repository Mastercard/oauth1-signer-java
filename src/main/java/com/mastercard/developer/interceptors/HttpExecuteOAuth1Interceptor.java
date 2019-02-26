package com.mastercard.developer.interceptors;

import com.google.api.client.http.HttpExecuteInterceptor;
import com.google.api.client.http.HttpRequest;
import com.mastercard.developer.signers.GoogleApiClientSigner;

import java.io.IOException;
import java.security.PrivateKey;

/**
 * A Google Client API interceptor for computing and adding an OAuth1 authorization header to HTTP requests.
 * See also: https://developers.google.com/api-client-library/java/google-http-java-client/reference/1.20.0/com/google/api/client/http/HttpExecuteInterceptor.
 */
public class HttpExecuteOAuth1Interceptor implements HttpExecuteInterceptor {

    private final GoogleApiClientSigner signer;

    public HttpExecuteOAuth1Interceptor(String consumerKey, PrivateKey signingKey) {
        this.signer = new GoogleApiClientSigner(consumerKey, signingKey);
    }

    public void intercept(HttpRequest request) throws IOException {
        signer.sign(request);
    }
}