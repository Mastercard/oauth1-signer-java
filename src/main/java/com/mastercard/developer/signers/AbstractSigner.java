package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;
import com.mastercard.developer.oauth.SignatureMethod;

import java.nio.charset.Charset;
import java.security.PrivateKey;

public abstract sealed class AbstractSigner permits ApacheHttpClient4Signer, GoogleApiClientSigner, HttpsUrlConnectionSigner, OkHttp2Signer, OkHttpSigner, OpenFeignSigner, SpringHttpRequestSigner, SpringWebfluxSigner{

  protected final String consumerKey;
  protected final PrivateKey signingKey;
  protected final Charset charset;
  protected final SignatureMethod signatureMethod;

  protected AbstractSigner(String consumerKey, PrivateKey signingKey) {
    this(Charset.defaultCharset(), consumerKey, signingKey, OAuth.DEFAULT_SIGNATURE_METHOD);
  }

  protected AbstractSigner(String consumerKey, PrivateKey signingKey, SignatureMethod signatureMethod) {
    this(Charset.defaultCharset(), consumerKey, signingKey, signatureMethod);
  }

  protected AbstractSigner(Charset charset, String consumerKey, PrivateKey signingKey, SignatureMethod signatureMethod) {
    this.consumerKey = consumerKey;
    this.signingKey = signingKey;
    this.charset = charset;
    this.signatureMethod = signatureMethod;
  }
}
