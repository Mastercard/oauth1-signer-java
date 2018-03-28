package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import javax.net.ssl.HttpsURLConnection;

/**
 * Utility method for signing Java HttpsURLConnection requests.
 */
public class HttpsUrlConnectionSigner extends AbstractSigner {
  private final Charset charset;

  public HttpsUrlConnectionSigner(Charset charset, String consumerKey, PrivateKey signingKey) {
    super(consumerKey, signingKey);
    this.charset = charset;
  }

  public void sign(HttpsURLConnection req, String payload) {
    URI uri;
    try {
      uri = req.getURL().toURI();
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("The provided URL could not be converted to an URI representation", e);
    }
    String method = req.getRequestMethod();

    String authHeader = OAuth.getAuthorizationHeader(uri, method, payload, charset, consumerKey, signingKey);
    req.setRequestProperty(OAuth.AUTHORIZATION_HEADER_NAME, authHeader);
  }
}
