package com.mastercard.developer.signers;

import java.nio.charset.Charset;
import java.security.PrivateKey;

public abstract class AbstractSigner {

  protected final String consumerKey;
  protected final PrivateKey signingKey;
  protected final Charset charset;

  public AbstractSigner(String consumerKey, PrivateKey signingKey) {
    this(Charset.defaultCharset(), consumerKey, signingKey);
  }

  public AbstractSigner(Charset charset, String consumerKey, PrivateKey signingKey) {
    this.consumerKey = consumerKey;
    this.signingKey = signingKey;
    this.charset = charset;
  }
}
