package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;
import feign.RequestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.security.PrivateKey;

public class OpenFeignSigner extends AbstractSigner {

    private final String baseUri;

    public OpenFeignSigner(String consumerKey, PrivateKey signingKey, String baseUri) {
        super(consumerKey, signingKey);
        this.baseUri = baseUri;
    }

    public OpenFeignSigner(Charset charset, String consumerKey, PrivateKey signingKey, String baseUri) {
        super(charset, consumerKey, signingKey);
        this.baseUri = baseUri;
    }

    public void sign(RequestTemplate requestTemplate) {
        URI uri;
        try {
            uri = new URI(baseUri.replaceAll("/$", "") + requestTemplate.request().url());
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("The provided URL could not be converted to an URI representation", e);
        }
        String method = requestTemplate.method();
        String payload = new String(requestTemplate.body(), charset);
        String authHeader = OAuth.getAuthorizationHeader(uri, method, payload, charset, consumerKey, signingKey);
        requestTemplate.header(OAuth.AUTHORIZATION_HEADER_NAME, authHeader);
    }
}
