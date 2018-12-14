package com.mastercard.developer.interceptors;

import com.mastercard.developer.signers.OpenFeignSigner;
import feign.RequestInterceptor;
import feign.RequestTemplate;

import java.security.PrivateKey;

/**
 * An OpenFeign request interceptor for computing and adding an OAuth1 authorization header to HTTP requests.
 * See also: https://github.com/OpenFeign/feign
 */
public class OpenFeignOAuth1Interceptor implements RequestInterceptor {

    private final OpenFeignSigner signer;

    public OpenFeignOAuth1Interceptor(String consumerKey, PrivateKey signingKey, String baseUri) {
        this.signer = new OpenFeignSigner(consumerKey, signingKey, baseUri);
    }

    @Override
    public void apply(RequestTemplate requestTemplate) {
        signer.sign(requestTemplate);
    }
}
