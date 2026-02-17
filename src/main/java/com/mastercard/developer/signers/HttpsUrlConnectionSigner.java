package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;
import com.mastercard.developer.oauth.SignatureMethod;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import javax.net.ssl.HttpsURLConnection;

/**
 * Utility class for signing Java HttpsURLConnection requests.
 */
public class HttpsUrlConnectionSigner extends AbstractSigner {

  public HttpsUrlConnectionSigner(Charset charset, String consumerKey, PrivateKey signingKey) {
    super(charset, consumerKey, signingKey, OAuth.DEFAULT_SIGNATURE_METHOD);
  }

  public HttpsUrlConnectionSigner(Charset charset, String consumerKey, PrivateKey signingKey, SignatureMethod signatureMethod) {
    super(charset, consumerKey, signingKey, signatureMethod);
  }

  public void sign(HttpsURLConnection req, String payload) {
    URI uri;
    try {
      uri = req.getURL().toURI();
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("The provided URL could not be converted to an URI representation", e);
    }
    String method = req.getRequestMethod();
    String authHeader = OAuth.getAuthorizationHeader(uri, method, payload, charset, consumerKey, signingKey, signatureMethod);
    req.setRequestProperty(OAuth.AUTHORIZATION_HEADER_NAME, authHeader);
  }
}
