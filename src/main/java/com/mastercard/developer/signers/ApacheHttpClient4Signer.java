package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.PrivateKey;

import com.mastercard.developer.oauth.SignatureMethod;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.ContentType;
import org.apache.http.util.EntityUtils;

/**
 * Utility class for signing Apache HTTP Client 4 requests.
 */
public class ApacheHttpClient4Signer extends AbstractSigner {

  public ApacheHttpClient4Signer(String consumerKey, PrivateKey signingKey) {
    super(consumerKey, signingKey);
  }

  public ApacheHttpClient4Signer(String consumerKey, PrivateKey signingKey, SignatureMethod signatureMethod) {
    super(consumerKey, signingKey, signatureMethod);
  }

  public void sign(HttpRequestBase req) throws IOException {
    String payload = null;
    Charset charset = Charset.defaultCharset();
    if (HttpEntityEnclosingRequestBase.class.isAssignableFrom(req.getClass())) {
      HttpEntityEnclosingRequestBase requestBase = (HttpEntityEnclosingRequestBase) req;
      HttpEntity entity = requestBase.getEntity();
      if (entity.getContentLength() > 0) {
        if (!entity.isRepeatable()) {
          throw new IOException(
              "The signer needs to read the request payload but the input stream of this request cannot be read multiple times. Please provide the payload using a separate argument or ensure that the entity is repeatable.");
        }
        ContentType contentType = ContentType.get(entity);
        charset = contentType.getCharset();
        payload = EntityUtils.toString(entity, contentType.getCharset());
      }
    }

    String authHeader = OAuth.getAuthorizationHeader(req.getURI(), req.getMethod(), payload, charset, consumerKey, signingKey, signatureMethod);
    req.setHeader(OAuth.AUTHORIZATION_HEADER_NAME, authHeader);
  }
}
