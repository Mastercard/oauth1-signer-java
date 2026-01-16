package com.mastercard.developer.signers;

import java.nio.charset.Charset;
import java.security.PrivateKey;

public abstract sealed class AbstractSigner permits ApacheHttpClient4Signer, GoogleApiClientSigner, HttpsUrlConnectionSigner, OkHttp2Signer, OkHttpSigner, OpenFeignSigner, SpringHttpRequestSigner, SpringWebfluxSigner{

  protected final String consumerKey;
  protected final PrivateKey signingKey;
  protected final Charset charset;

  protected AbstractSigner(String consumerKey, PrivateKey signingKey) {
    this(Charset.defaultCharset(), consumerKey, signingKey);
  }

  protected AbstractSigner(Charset charset, String consumerKey, PrivateKey signingKey) {
    this.consumerKey = consumerKey;
    this.signingKey = signingKey;
    this.charset = charset;
  }
}
