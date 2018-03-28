package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import okhttp3.Request;
import okio.Buffer;

/**
 * Utility method for signing Java OkHttp requests.
 */
public class OkHttpSigner extends AbstractSigner {
  private final Charset charset;

  public OkHttpSigner(String consumerKey, PrivateKey signingKey) {
    super(consumerKey, signingKey);
    //OkHttp uses UTF-8 by default
    this.charset = Charset.forName("UTF-8");
  }

  public void sign(Request.Builder req) throws IOException {
    Request builtRequest = req.build();

    URI uri = builtRequest.url().uri();
    String method = builtRequest.method();
    String payload = null;

    if (builtRequest.body().contentLength() > 0) {
      Buffer buffer = new Buffer();
      builtRequest.body().writeTo(buffer);
      payload = buffer.readUtf8();
    }

    String authHeader = OAuth.getAuthorizationHeader(uri, method, payload, charset, consumerKey, signingKey);
    req.addHeader(OAuth.AUTHORIZATION_HEADER_NAME, authHeader);
  }
}
