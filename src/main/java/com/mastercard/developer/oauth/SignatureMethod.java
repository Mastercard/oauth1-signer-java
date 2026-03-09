package com.mastercard.developer.oauth;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * Supported OAuth 1.0 signature methods
 */
public enum SignatureMethod {

    /**
     * RSA-SHA256 signature method.
     * <p>Uses the {@code SHA256withRSA} JCA algorithm (RSASSA-PKCS1-v1_5 with SHA-256).</p>
     *
     * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#signature-algorithms">Java Signature Algorithms</a>
     */
    RSA_SHA256("SHA256withRSA", "RSA-SHA256", null),

    /**
     * RSA-PSS signature method.
     * <p>Uses the {@code RSASSA-PSS} JCA algorithm with the following parameters:</p>
     * <ul>
     *   <li>Digest: SHA-256</li>
     *   <li>Mask generation function: MGF1 with SHA-256</li>
     *   <li>Salt length: 32 bytes</li>
     * </ul>
     *
     * @see <a href="https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#signature-algorithms">Java Signature Algorithms</a>
     */
    RSA_PSS_SHA256("RSASSA-PSS", "RSA-PSS", new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));

    /** JCA signature algorithm name. */
    private final String jcaName;
    /** OAuth signature method name. */
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
