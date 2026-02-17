package com.mastercard.developer.oauth;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public enum SignatureMethod {

    RSA_SHA256("SHA256withRSA", "RSA-SHA256", null),
    RSA_PSS_SHA256("RSASSA-PSS", "RSA-PSS", new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));

    private final String jcaName;
    private final String oAuthName;
    private final AlgorithmParameterSpec algorithmParams;


    SignatureMethod(String jcaName, String oAuthName, AlgorithmParameterSpec algorithmParams) {
        this.jcaName = jcaName;
        this.oAuthName = oAuthName;
        this.algorithmParams = algorithmParams;
    }

    String getOauthName() {
        return oAuthName;
    }

    String getJcaName() {
        return jcaName;
    }

    AlgorithmParameterSpec getAlgorithmParams() {
        return algorithmParams;
    }
}
