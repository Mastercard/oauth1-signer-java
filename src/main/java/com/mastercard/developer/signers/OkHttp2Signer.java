package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;
import com.squareup.okhttp.*;
import okio.Buffer;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.security.PrivateKey;


/**
 * Utility class for signing Java OkHttp2 requests.
 */
public class OkHttp2Signer extends AbstractSigner {

    public OkHttp2Signer(String consumerKey, PrivateKey signingKey) {
        super(Charset.forName("UTF-8"), consumerKey, signingKey);
    }

    public OkHttp2Signer(Charset charset, String consumerKey, PrivateKey signingKey) {
        super(charset, consumerKey, signingKey);
    }

    public void sign(Request.Builder req) throws IOException {
        Request builtRequest = req.build();

        URI uri = builtRequest.uri();
        String method = builtRequest.method();
        String payload = null;

        RequestBody body = builtRequest.body();
        if (null != body && body.contentLength() > 0) {
            Buffer buffer = new Buffer();
            builtRequest.body().writeTo(buffer);
            payload = buffer.readUtf8();
        }

        String authHeader = OAuth.getAuthorizationHeader(uri, method, payload, charset, consumerKey, signingKey);
        req.addHeader(OAuth.AUTHORIZATION_HEADER_NAME, authHeader);
    }
}
