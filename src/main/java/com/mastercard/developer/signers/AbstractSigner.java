package com.mastercard.developer.signers;

import java.security.PrivateKey;

public abstract class AbstractSigner {
  protected final String consumerKey;
  protected final PrivateKey signingKey;

  public AbstractSigner(String consumerKey, PrivateKey signingKey) {
    this.consumerKey = consumerKey;
    this.signingKey = signingKey;
  }
}
