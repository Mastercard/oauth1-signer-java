package com.mastercard.developer.oauth;

import java.net.URI;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Performs OAuth1.0a compliant signing with body hash support for non-urlencoded content types.
 */
public class OAuth {

  public static final String EMPTY_STRING = "";
  public static final String AUTHORIZATION_HEADER_NAME = "Authorization";
  private static final String SHA_256_WITH_RSA = "SHA256withRSA";
  private static final String RSASSA_PSS = "RSASSA-PSS";
  private static final String MGF_1 = "MGF1";
  private static final int RSAPSS_SALT_LENGTH = 32;
  private static final int TRAILER_FIELD = 1;
  private static final Logger LOG = Logger.getLogger(OAuth.class.getName());
  private static final String HASH_ALGORITHM = "SHA-256";
  private static final int NONCE_LENGTH = 16;
  private static final String ALPHA_NUMERIC_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private OAuth() {
  }

  /**
   * Creates a Mastercard API compliant OAuth Authorization header
   *
   * @param uri Target URI for this request
   * @param method HTTP method of the request
   * @param payload Payload (nullable)
   * @param charset Charset encoding of the request
   * @param consumerKey Consumer key set up in a Mastercard Developer Portal project
   * @param signingKey The private key that will be used for signing the request that corresponds to the consumerKey
   * @return Valid OAuth1.0a signature with a body hash when payload is present
   */
  public static String getAuthorizationHeader(URI uri, String method, String payload, Charset charset, String consumerKey, PrivateKey signingKey) {
    if (uri == null || method == null || charset == null || consumerKey == null || signingKey == null) {
      throw new IllegalArgumentException("Required parameters (uri, method, charset, consumerKey, signingKey) must not be null");
    }

    TreeMap<String, List<String>> queryParams = extractQueryParams(uri, charset);

    HashMap<String, String> oauthParams = new HashMap<>();
    oauthParams.put("oauth_consumer_key", consumerKey);
    oauthParams.put("oauth_nonce", getNonce());
    oauthParams.put("oauth_timestamp", getTimestamp());
    oauthParams.put("oauth_version", "1.0");
    oauthParams.put("oauth_body_hash", getBodyHash(payload, charset, HASH_ALGORITHM));

    // Combine query and oauth_ parameters into lexicographically sorted string
    String paramString = toOauthParamString(queryParams, oauthParams);

    // Normalized URI without query params and fragment
    String baseUri = getBaseUriString(uri);

    // Signature base string
    String sbs = getSignatureBaseString(method, baseUri, paramString, charset);
    String signature = signSignatureBaseString(sbs, signingKey, charset, oauthParams);

    return getAuthorizationString(oauthParams);
  }

  /**
   * Generate a valid signature base string as per
   * https://tools.ietf.org/html/rfc5849#section-3.4.1
   *
   * @param httpMethod HTTP method of the request
   * @param baseUri Base URI that conforms with https://tools.ietf.org/html/rfc5849#section-3.4.1.2
   * @param paramString OAuth parameter string that conforms with https://tools.ietf.org/html/rfc5849#section-3.4.1.3
   * @param charset Charset encoding of the request
   * @return A correctly constructed and escaped signature base string
   */
  static String getSignatureBaseString(String httpMethod, String baseUri, String paramString, Charset charset) {
    String sbs =
        // Uppercase HTTP method
        httpMethod.toUpperCase() + "&" +
        // Base URI
        Util.percentEncode(baseUri, charset) + "&" +
        // OAuth parameter string
        Util.percentEncode(paramString, charset);

    LOG.log(Level.FINE, "Generated SBS: {0}", sbs);
    return sbs;
  }

  /**
   * Parse query parameters out of the URL.
   * https://tools.ietf.org/html/rfc5849#section-3.4.1.3
   *
   * @param uri URL containing all query parameters that need to be signed
   * @param charset Charset encoding of the request
   * @return Sorted map of query parameter key/value pairs. Values for parameters with the same name are added into a list.
   */
  static TreeMap<String, List<String>> extractQueryParams(URI uri, Charset charset) {

    final String decodedQueryString = uri.getQuery();
    final String rawQueryString =  uri.getRawQuery();
    if (decodedQueryString == null || decodedQueryString.isEmpty()
            || rawQueryString == null || rawQueryString.isEmpty()) {
      // No query params
      return new TreeMap<>();
    }

    boolean mustEncode = !decodedQueryString.equals(rawQueryString);
    final TreeMap<String, List<String>> queryPairs = new TreeMap<>();
    final String[] pairs = decodedQueryString.split("&");
    for (String pair : pairs) {
      final int idx = pair.indexOf('=');
      String key = idx > 0 ? pair.substring(0, idx) : pair;
      if (!queryPairs.containsKey(key)) {
        key = mustEncode ? Util.percentEncode(key, charset) : key;
        List<String> list = new LinkedList<>();
        queryPairs.put(key, list);
      }
      String value = idx > 0 && pair.length() > idx + 1 ? pair.substring(idx + 1) : EMPTY_STRING;
      value = mustEncode ? Util.percentEncode(value, charset) : value;
      queryPairs.get(key).add(value);
    }

    return queryPairs;
  }

  /**
   * Lexicographically sort all parameters and concatenate them into a string as per
   * https://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
   *
   * @param queryParamsMap Sorted map of all oauth parameters that need to be signed
   * @param oauthParamsMap Map of OAuth parameters to be included in Authorization header
   * @return Correctly encoded and sorted OAuth parameter string
   */
  static String toOauthParamString(SortedMap<String, List<String>> queryParamsMap, Map<String, String> oauthParamsMap) {
    TreeMap<String, List<String>> consolidatedParams = new TreeMap<>(queryParamsMap);

    // Add OAuth params to consolidated params map
    for (Map.Entry<String, String> entry : oauthParamsMap.entrySet()) {
      if (consolidatedParams.containsKey(entry.getKey())) {
        consolidatedParams.get(entry.getKey()).add(entry.getValue());
      } else {
        consolidatedParams.put(entry.getKey(), Arrays.asList(entry.getValue()));
      }
    }

    StringBuilder oauthParams = new StringBuilder();

    // Add all parameters to the parameter string for signing
    for (Map.Entry<String, List<String>> entry : consolidatedParams.entrySet()) {
      String key = entry.getKey();

      // Keys with same name are sorted by their values
      if (entry.getValue().size() > 1) {
        Collections.sort(entry.getValue());
      }

      for (String value : entry.getValue()) {
        oauthParams.append(key).append("=").append(value).append("&");
      }
    }

    // Remove trailing ampersand
    if (oauthParams.length() > 0 && oauthParams.charAt(oauthParams.length() - 1) == '&') {
      oauthParams.deleteCharAt(oauthParams.length() - 1);
    }

    return oauthParams.toString();
  }

  /**
   * Generates a random string for replay protection as per
   * https://tools.ietf.org/html/rfc5849#section-3.3
   *
   * @return Random string of 16 characters
   */
  static String getNonce() {
    StringBuilder sb = new StringBuilder(NONCE_LENGTH);
    for (int i = 0; i < NONCE_LENGTH; i++) {
      sb.append(ALPHA_NUMERIC_CHARS.charAt(SECURE_RANDOM.nextInt(ALPHA_NUMERIC_CHARS.length())));
    }
    return sb.toString();
  }

  /**
   * Returns UNIX Timestamp as required per
   * https://tools.ietf.org/html/rfc5849#section-3.3
   *
   * @return UNIX timestamp (UTC)
   */
  private static String getTimestamp() {
    return Long.toString(System.currentTimeMillis() / 1000L);
  }

  /**
   * Normalizes the URL as per
   * https://tools.ietf.org/html/rfc5849#section-3.4.1.2
   *
   * @param uri URL that will be called as part of this request
   * @return Normalized URL
   */
  static String getBaseUriString(URI uri) {
    // Lowercase scheme and authority
    String scheme = uri.getScheme();
    String authority = uri.getAuthority();

    if (scheme == null || authority == null) {
      throw new IllegalArgumentException("URI must have both scheme and authority");
    }

    scheme = scheme.toLowerCase();
    authority = authority.toLowerCase();

    // Remove port if it matches the default for scheme
    if (("http".equals(scheme) && uri.getPort() == 80)
        || ("https".equals(scheme) && uri.getPort() == 443)) {
      int index = authority.lastIndexOf(':');
      if (index >= 0) {
        authority = authority.substring(0, index);
      }
    }

    String path = uri.getRawPath();
    if (path == null || path.length() <= 0) {
      path = "/";
    }

    return scheme + "://" + authority + path;
  }

  /**
   * Generates a hash based on request payload as per
   * https://tools.ietf.org/id/draft-eaton-oauth-bodyhash-00.html
   *
   * @param payload Request payload
   * @param charset Charset encoding of the request
   * @param hashAlg Hash algorithm name (e.g., "SHA-256")
   * @return Base64 encoded cryptographic hash of the given payload
   */
  static String getBodyHash(String payload, Charset charset, String hashAlg) {
    MessageDigest digest;

    try {
      digest = MessageDigest.getInstance(hashAlg);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("Unable to obtain " + hashAlg + " message digest", e);
    }

    digest.reset();
    // "If the request does not have an entity body, the hash should be taken over the empty string"
    byte[] byteArray = (payload == null) ? "".getBytes(charset) : payload.getBytes(charset);
    byte[] hash = digest.digest(byteArray);

    return Util.b64Encode(hash);
  }

  /**
   * Signs the OAuth signature base string using an RSA private key.
   *
   * <p>This method detects which signature algorithm is supported by the current provider:
   * <ol>
   *   <li>Probes if {@code SHA256withRSA} supports PSS parameters (it shouldn't, triggering an exception)</li>
   *   <li>On expected failure, attempts {@code SHA256withRSA} (RSA PKCS#1 v1.5) signing first</li>
   *   <li>If {@code SHA256withRSA} fails, falls back to {@code RSASSA-PSS} with parameters:
   *       SHA-256 / MGF1(SHA-256) / saltLen=32 / trailerField=1</li>
   * </ol>
   *
   * <p>The method sets {@code oauth_signature_method} in the provided {@code oauthParams} map:
   * <ul>
   *   <li>{@code "RSA-SHA256"} when using SHA256withRSA (PKCS#1 v1.5)</li>
   *   <li>{@code "RSA-PSS"} when using RSASSA-PSS</li>
   * </ul>
   *
   * @param sbs         Signature base string formatted as per RFC 5849 section 3.4.1
   * @param signingKey  Private key of the RSA key pair that was established with the service provider
   * @param charset     Charset encoding of the request
   * @param oauthParams Map of OAuth parameters where {@code oauth_signature_method} will be set based on the algorithm used
   * @return Base64-encoded RSA signature of the signature base string
   */
  static String signSignatureBaseString(String sbs, PrivateKey signingKey, Charset charset, HashMap<String, String> oauthParams) {
    // Probe algorithm support: SHA256withRSA should reject PSS parameters, triggering fallback to standard RSA signing first
    String signature = null;
    try {
      Signature signer = Signature.getInstance(SHA_256_WITH_RSA);
      signer.setParameter(new PSSParameterSpec(
              HASH_ALGORITHM,
              MGF_1,
              MGF1ParameterSpec.SHA256,
              RSAPSS_SALT_LENGTH,
              TRAILER_FIELD));
    } catch (GeneralSecurityException e) {
      try {
        signature = doSignSHA256(sbs, signingKey, charset);
        oauthParams.put("oauth_signature_method", "RSA-SHA256");
      } catch (Exception ex) { // Catch any exception from SHA256withRSA signing and fall back to PSS
        signature = doSignWithPss(sbs, signingKey, charset);
        oauthParams.put("oauth_signature_method", "RSA-PSS");
      }
    }
    oauthParams.put("oauth_signature", Util.percentEncode(signature, charset));
    return  signature;
  }

  static String doSignWithPss(String sbs, PrivateKey signingKey, Charset charset) {
    if (signingKey == null) {
      throw new IllegalArgumentException("signingKey must not be null");
    }

    try {
      Signature signer = Signature.getInstance(RSASSA_PSS);
      signer.setParameter(new PSSParameterSpec(
          HASH_ALGORITHM,
          MGF_1,
          MGF1ParameterSpec.SHA256,
          RSAPSS_SALT_LENGTH,
          TRAILER_FIELD));
      return doSign(sbs, signingKey, charset, signer);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Unable to sign OAuth signature base string", e);
    }
  }

  static String doSignSHA256(String sbs, PrivateKey signingKey, Charset charset) {
    if (signingKey == null) {
      throw new IllegalArgumentException("signingKey must not be null");
    }
    try {
      Signature signer = Signature.getInstance(SHA_256_WITH_RSA);
      return doSign(sbs, signingKey, charset, signer);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Unable to sign OAuth signature base string using " + SHA_256_WITH_RSA, e);
    }
  }

  static String doSign(String sbs, PrivateKey signingKey, Charset charset, Signature signer) throws GeneralSecurityException {
    signer.initSign(signingKey);
    signer.update(sbs.getBytes(charset));
    return Util.b64Encode(signer.sign());
  }

  /**
   * Constructs a valid Authorization header as per
   * https://tools.ietf.org/html/rfc5849#section-3.5.1
   *
   * @param oauthParams Map of OAuth parameters to be included in the Authorization header
   * @return Correctly formatted header
   */
  private static String getAuthorizationString(Map<String, String> oauthParams) {
    StringBuilder header = new StringBuilder("OAuth ");
    for (Map.Entry<String, String> param : oauthParams.entrySet()) {
      header.append(param.getKey()).append("=\"")
          .append(param.getValue()).append("\",");
    }
    // Remove trailing ,
    header.deleteCharAt(header.length() - 1);
    return header.toString();
  }
}
