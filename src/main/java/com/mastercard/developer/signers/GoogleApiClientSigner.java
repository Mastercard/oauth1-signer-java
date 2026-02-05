package com.mastercard.developer.signers;

import com.google.api.client.http.HttpContent;
import com.google.api.client.http.HttpRequest;
import com.mastercard.developer.oauth.OAuth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.security.PrivateKey;

/**
 * Utility class for signing Google HTTP Client requests.
 * See also: https://github.com/googleapis/google-http-java-client
 */
public final class GoogleApiClientSigner extends AbstractSigner {

    public GoogleApiClientSigner(String consumerKey, PrivateKey signingKey) {
        super(consumerKey, signingKey);
    }

    public GoogleApiClientSigner(Charset charset, String consumerKey, PrivateKey signingKey) {
        super(charset, consumerKey, signingKey);
    }

    public void sign(HttpRequest request) throws IOException {
        URI uri = request.getUrl().toURI();
        String method = request.getRequestMethod();
        String payload = null;

        HttpContent content = request.getContent();
        if (null != content && content.getLength() > 0) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            content.writeTo(outputStream);
            payload = outputStream.toString(charset.name());
        }

        String authorizationHeader = OAuth.getAuthorizationHeader(uri, method, payload, charset, consumerKey, signingKey);
        request.getHeaders().setAuthorization(authorizationHeader);
    }
}
