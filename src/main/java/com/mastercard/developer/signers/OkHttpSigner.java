package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;

import com.mastercard.developer.oauth.SignatureMethod;
import okhttp3.Request;
import okhttp3.RequestBody;
import okio.Buffer;

/**
 * Utility class for signing Java OkHttp3 requests.
 */
public final class OkHttpSigner extends AbstractSigner {

  public OkHttpSigner(String consumerKey, PrivateKey signingKey) {
    super(StandardCharsets.UTF_8, consumerKey, signingKey, OAuth.DEFAULT_SIGNATURE_METHOD);
  }

  public OkHttpSigner(String consumerKey, PrivateKey signingKey, SignatureMethod signatureMethod) {
    super(StandardCharsets.UTF_8, consumerKey, signingKey, signatureMethod);
  }

  public OkHttpSigner(Charset charset, String consumerKey, PrivateKey signingKey) {
    super(charset, consumerKey, signingKey, OAuth.DEFAULT_SIGNATURE_METHOD);
  }

  public OkHttpSigner(Charset charset, String consumerKey, PrivateKey signingKey, SignatureMethod signatureMethod) {
    super(charset, consumerKey, signingKey, signatureMethod);
  }

  public void sign(Request.Builder req) throws IOException {
    Request builtRequest = req.build();

    URI uri = builtRequest.url().uri();
    String method = builtRequest.method();
    String payload = null;

    RequestBody body = builtRequest.body();
    if (null != body && body.contentLength() > 0) {
      Buffer buffer = new Buffer();
      builtRequest.body().writeTo(buffer);
      payload = buffer.readUtf8();
    }

    String authHeader = OAuth.getAuthorizationHeader(uri, method, payload, charset, consumerKey, signingKey, signatureMethod);
    req.addHeader(OAuth.AUTHORIZATION_HEADER_NAME, authHeader);
  }
}
