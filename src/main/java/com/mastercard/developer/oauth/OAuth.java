package com.mastercard.developer.oauth;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.security.*;
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

  private OAuth() {
  }

  public static final String EMPTY_STRING = "";
  public static final String AUTHORIZATION_HEADER_NAME = "Authorization";

  private static final Logger LOG = Logger.getLogger(OAuth.class.getName());
  private static final String HASH_ALGORITHM = "SHA-256";
  private static final int NONCE_LENGTH = 16;
  private static final String ALPHA_NUMERIC_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

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
    TreeMap<String, List<String>> queryParams = extractQueryParams(uri, charset);

    HashMap<String, String> oauthParams = new HashMap<>();
    oauthParams.put("oauth_consumer_key", consumerKey);
    oauthParams.put("oauth_nonce", getNonce());
    oauthParams.put("oauth_signature_method", "RSA-" + HASH_ALGORITHM.replace("-", ""));
    oauthParams.put("oauth_timestamp", getTimestamp());
    oauthParams.put("oauth_version", "1.0");
    oauthParams.put("oauth_body_hash", getBodyHash(payload, charset, HASH_ALGORITHM));

    // Combine query and oauth_ parameters into lexicographically sorted string
    String paramString = toOauthParamString(queryParams, oauthParams);

    // Normalized URI without query params and fragment
    String baseUri = getBaseUriString(uri);

    // Signature base string
    String sbs = getSignatureBaseString(method, baseUri, paramString, charset);

    // Signature
    String signature = signSignatureBaseString(sbs, signingKey, charset);
    oauthParams.put("oauth_signature", Util.percentEncode(signature, charset));

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
    final String queryParams = uri.getQuery();
    if (queryParams == null || queryParams.isEmpty()) {
      return new TreeMap<>();
    }

    final TreeMap<String, List<String>> queryPairs = new TreeMap<>();
    final String[] pairs = queryParams.split("&");
    for (String pair : pairs) {
      final int idx = pair.indexOf('=');
      String key = idx > 0 ? pair.substring(0, idx) : pair;
      if (!queryPairs.containsKey(key)) {
        key = Util.percentEncode(key, charset);
        queryPairs.put(key, new LinkedList<String>());
      }
      String value = idx > 0 && pair.length() > idx + 1 ? pair.substring(idx + 1) : EMPTY_STRING;
      value = Util.percentEncode(value, charset);
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
    int stringLength = oauthParams.length() - 1;
    if (oauthParams.charAt(stringLength) == '&') {
      oauthParams.deleteCharAt(stringLength);
    }

    return oauthParams.toString();
  }

  /**
   * Generates a random string for replay protection as per
   * https://tools.ietf.org/html/rfc5849#section-3.3
   *
   * @return random string of 16 characters.
   */
  static String getNonce() {
    SecureRandom rnd = new SecureRandom();
    StringBuilder sb = new StringBuilder(NONCE_LENGTH);
    for (int i = 0; i < NONCE_LENGTH; i++) {
      sb.append(ALPHA_NUMERIC_CHARS.charAt(rnd.nextInt(ALPHA_NUMERIC_CHARS.length())));
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
    String scheme = uri.getScheme().toLowerCase();
    String authority = uri.getAuthority().toLowerCase();

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

    try {
      // Remove query and fragment
      return new URI(scheme, authority, path, null, null).toString();
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("Unable to normalize provided URL due to: " + e.getMessage());
    }
  }

  /**
   * Generates a hash based on request payload as per
   * https://tools.ietf.org/id/draft-eaton-oauth-bodyhash-00.html
   *
   * @param payload Request payload
   * @param charset Charset encoding of the request
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
    byte[] byteArray = null == payload ? "".getBytes() : payload.getBytes(charset); //
    byte[] hash = digest.digest(byteArray);

    return Util.b64Encode(hash);
  }

  /**
   * Signs the signature base string using an RSA private key. The methodology is described at
   * https://tools.ietf.org/html/rfc5849#section-3.4.3 but Mastercard uses the stronger SHA-256 algorithm
   * as a replacement for the described SHA1 which is no longer considered secure.
   *
   * @param sbs Signature base string formatted as per https://tools.ietf.org/html/rfc5849#section-3.4.1
   * @param signingKey Private key of the RSA key pair that was established with the service provider
   * @param charset Charset encoding of the request
   * @return RSA signature matching the contents of signature base string
   */
  static String signSignatureBaseString(String sbs, PrivateKey signingKey, Charset charset) {
    try {
      Signature signer = Signature.getInstance("SHA256withRSA");
      signer.initSign(signingKey);
      byte[] sbsBytes = sbs.getBytes(charset);
      signer.update(sbsBytes);
      byte[] signatureBytes = signer.sign();
      return Util.b64Encode(signatureBytes);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("Unable to RSA-SHA256 sign the given string with the provided key", e);
    }
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
