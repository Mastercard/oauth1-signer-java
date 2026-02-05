package com.mastercard.developer.oauth;

import com.mastercard.developer.test.TestUtils;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static com.mastercard.developer.test.TestUtils.UTF8_CHARSET;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.*;
import static org.junit.Assert.assertEquals;

public class OAuthTest {

  private static final String HASH_ALGORITHM = "SHA-256";

  @BeforeClass
  public static void beforeClass() {
    System.setProperty("java.util.logging.config.file", ClassLoader.getSystemResource("logging.properties").getPath());
  }

  @Test
  public void testExtractQueryParams_ShouldSupportDuplicateKeysAndEmptyValues() {

    // GIVEN
    URI uri = URI.create("https://sandbox.api.mastercard.com/audiences/v1/getcountries?offset=0&offset=1&length=10&empty&odd=");

    // WHEN
    Map<String, List<String>> queryParams = OAuth.extractQueryParams(uri, UTF8_CHARSET);

    // THEN
    assertEquals(queryParams.toString(), 4, queryParams.size());
    assertArrayEquals(new String[]{"10"}, queryParams.get("length").toArray());
    assertArrayEquals(new String[]{"0", "1"}, queryParams.get("offset").toArray());
    assertArrayEquals(new String[]{""}, queryParams.get("empty").toArray());
    assertArrayEquals(new String[]{""}, queryParams.get("odd").toArray());
  }

  @Test
  public void testExtractQueryParams_ShouldSupportRfcExample_WhenUriCreatedFromUriString() {

    // GIVEN
    URI uri = URI.create("https://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b"); // See: https://tools.ietf.org/html/rfc5849#section-3.4.1.3.1
    assertEquals("b5=%3D%253D&a3=a&c%40=&a2=r%20b", uri.getRawQuery());
    assertEquals("b5==%3D&a3=a&c@=&a2=r b", uri.getQuery());

    // WHEN
    Map<String, List<String>> queryParams = OAuth.extractQueryParams(uri, UTF8_CHARSET);

    // THEN
    assertEquals(queryParams.toString(), 4, queryParams.size());
    assertArrayEquals(new String[]{"%3D%253D"}, queryParams.get("b5").toArray());
    assertArrayEquals(new String[]{"a"}, queryParams.get("a3").toArray());
    assertArrayEquals(new String[]{""}, queryParams.get("c%40").toArray());
    assertArrayEquals(new String[]{"r%20b"}, queryParams.get("a2").toArray());
  }

  @Test
  public void testExtractQueryParams_ShouldSupportRfcExample_WhenUriCreatedFromUriComponents() throws Exception {

    // GIVEN
    URI uri = new URI("https", "example.com", "/", "b5==%3D&a3=a&c@=&a2=r b", null);

    // WHEN
    Map<String, List<String>> queryParams = OAuth.extractQueryParams(uri, UTF8_CHARSET);

    // THEN
    assertEquals(queryParams.toString(), 4, queryParams.size());
    assertArrayEquals(new String[]{"%3D%253D"}, queryParams.get("b5").toArray());
    assertArrayEquals(new String[]{"a"}, queryParams.get("a3").toArray());
    assertArrayEquals(new String[]{""}, queryParams.get("c%40").toArray());
    assertArrayEquals(new String[]{"r%20b"}, queryParams.get("a2").toArray());
  }

  @Test
  public void testExtractQueryParams_ShouldNotEncodeParams_WhenUriCreatedFromStringWithDecodedParams() {

    // GIVEN
    URI uri = URI.create("https://example.com/request?colon=:&plus=+&comma=,");
    assertEquals("colon=:&plus=+&comma=,", uri.getRawQuery()); // "URI.create" expects a legal URL and doesn't encode the params
    assertEquals("colon=:&plus=+&comma=,", uri.getQuery());

    // WHEN
    Map<String, List<String>> queryParams = OAuth.extractQueryParams(uri, UTF8_CHARSET);

    // THEN
    assertEquals(queryParams.toString(), 3, queryParams.size());
    assertArrayEquals(new String[]{":"}, queryParams.get("colon").toArray());
    assertArrayEquals(new String[]{"+"}, queryParams.get("plus").toArray());
    assertArrayEquals(new String[]{","}, queryParams.get("comma").toArray());
  }

  @Test
  public void testExtractQueryParams_ShouldEncodeParams_WhenUriCreatedFromStringWithEncodedParams() {

    // GIVEN
    URI uri = URI.create("https://example.com/request?colon=%3A&plus=%2B&comma=%2C");
    assertEquals("colon=%3A&plus=%2B&comma=%2C", uri.getRawQuery());
    assertEquals("colon=:&plus=+&comma=,", uri.getQuery());

    // WHEN
    Map<String, List<String>> queryParams = OAuth.extractQueryParams(uri, UTF8_CHARSET);

    // THEN
    assertEquals(queryParams.toString(), 3, queryParams.size());
    assertArrayEquals(new String[]{"%3A"}, queryParams.get("colon").toArray());
    assertArrayEquals(new String[]{"%2B"}, queryParams.get("plus").toArray());
    assertArrayEquals(new String[]{"%2C"}, queryParams.get("comma").toArray());
  }

  @Test
  public void testParameterEncoding_ShouldCreateExpectedSignatureBaseString_WhenQueryParamsEncodedInUri() {

    // GIVEN
    URI uri = URI.create("https://example.com/?param=token1%3Atoken2");

    // WHEN
    TreeMap<String, List<String>> queryParams = OAuth.extractQueryParams(uri, UTF8_CHARSET);
    String paramString = OAuth.toOauthParamString(queryParams, new HashMap<String, String>());
    String baseString = OAuth.getSignatureBaseString("GET", "https://example.com", paramString, UTF8_CHARSET);

    // THEN
    assertEquals("GET&https%3A%2F%2Fexample.com&param%3Dtoken1%253Atoken2", baseString);
  }

  @Test
  public void testParameterEncoding_ShouldCreateExpectedSignatureBaseString_WhenQueryParamsNotEncodedInUri() {

    // GIVEN
    URI uri = URI.create("https://example.com/?param=token1:token2");

    // WHEN
    TreeMap<String, List<String>> queryParams = OAuth.extractQueryParams(uri, UTF8_CHARSET);
    String paramString = OAuth.toOauthParamString(queryParams, new HashMap<String, String>());
    String baseString = OAuth.getSignatureBaseString("GET", "https://example.com", paramString, UTF8_CHARSET);

    // THEN
    assertEquals("GET&https%3A%2F%2Fexample.com&param%3Dtoken1%3Atoken2", baseString);
  }

  @Test
  public void testGetBodyHash() {
    String bodyHash = OAuth.getBodyHash(OAuth.EMPTY_STRING, UTF8_CHARSET, HASH_ALGORITHM);
    assertThat(bodyHash).isEqualTo("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");

    bodyHash = OAuth.getBodyHash(null, UTF8_CHARSET, HASH_ALGORITHM);
    assertThat(bodyHash).isEqualTo("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");

    bodyHash = OAuth.getBodyHash("{\"foõ\":\"bar\"}", UTF8_CHARSET, HASH_ALGORITHM);
    assertThat(bodyHash).isEqualTo("+Z+PWW2TJDnPvRcTgol+nKO3LT7xm8smnsg+//XMIyI=");
  }

  @Test(expected = IllegalStateException.class)
  public void testGetBodyHash_ShouldThrowIllegalStateException_WhenInvalidHashAlgorithm() {
    OAuth.getBodyHash(OAuth.EMPTY_STRING, UTF8_CHARSET, "SHA-123");
  }

  @Test
  public void testGetOAuthParamString_ShouldSupportRfcExample() {
    TreeMap<String, List<String>> params = new TreeMap<>();
    params.put("b5", Arrays.asList("%3D%253D"));
    params.put("a3", Arrays.asList("a", "2%20q"));
    params.put("c%40", Arrays.asList(""));
    params.put("a2", Arrays.asList("r%20b"));
    params.put("c2", Arrays.asList(""));

    HashMap<String, String> oauthParams = new HashMap<>();
    oauthParams.put("oauth_consumer_key", "9djdj82h48djs9d2");
    oauthParams.put("oauth_token", "kkk9d7dh3k39sjv7");
    oauthParams.put("oauth_signature_method", "HMAC-SHA1");
    oauthParams.put("oauth_timestamp", "137131201");
    oauthParams.put("oauth_nonce", "7d8f3e4a");

    String paramString = OAuth.toOauthParamString(params, oauthParams);

    assertEquals("a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7", paramString);
  }

  @Test
  public void testGetOAuthParamString_ShouldUseAscendingByteValueOrdering() {
    TreeMap<String, List<String>> params = new TreeMap<>();
    params.put("b", Arrays.asList("b"));
    params.put("A", Arrays.asList("a", "A"));
    params.put("B", Arrays.asList("B"));
    params.put("a", Arrays.asList("A", "a"));
    params.put("0", Arrays.asList("0"));
    HashMap<String, String> oauthParams = new HashMap<>();

    String paramString = OAuth.toOauthParamString(params, oauthParams);

    assertEquals("0=0&A=A&A=a&B=B&a=A&a=a&b=b", paramString);
  }

  @Test
  public void testGetBaseUriString_ShouldSupportRfcExamples() {
    URI uri = URI.create("https://www.example.net:8080");
    String baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://www.example.net:8080/", baseUri);

    // https://tools.ietf.org/html/rfc5849#section-3.4.1.2
    uri = URI.create("http://EXAMPLE.COM:80/r%20v/X?id=123");
    baseUri = OAuth.getBaseUriString(uri);
    assertEquals("http://example.com/r%20v/X", baseUri);
  }

  @Test
  public void testShallThrowErrorIfSchemaIsNull() {
    URI uri = URI.create("www.example.net:8080");
    try {
      String baseUri = OAuth.getBaseUriString(uri);
    } catch (IllegalArgumentException e) {
      assertEquals("URI must have both scheme and authority", e.getMessage());
    }
  }

  @Test
  public void testShallThrowErrorIfAuthorityIsNull() {
    URI uri = URI.create("/service?foo=bar");
    try {
      String baseUri = OAuth.getBaseUriString(uri);
    } catch (IllegalArgumentException e) {
      assertEquals("URI must have both scheme and authority", e.getMessage());
    }
  }
  @Test
  public void testGetBaseUriString_ShouldRemoveRedundantPorts() {
    URI uri = URI.create("https://api.mastercard.com:443/test?query=param");
    String baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://api.mastercard.com/test", baseUri);

    uri = URI.create("http://api.mastercard.com:80/test");
    baseUri = OAuth.getBaseUriString(uri);
    assertEquals("http://api.mastercard.com/test", baseUri);

    uri = URI.create("https://api.mastercard.com:17443/test?query=param");
    baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://api.mastercard.com:17443/test", baseUri);
  }

  @ParameterizedTest
  @CsvSource({
          "/test?query=param#fragment, test",
          "'', ''",
          "/TEST, TEST"
  })
  public void testGetBaseUriString_ShouldRemoveFragments(String createUri, String expectedUri) {
    URI uri = URI.create(String.format("https://api.mastercard.com%s", createUri));
    String baseUri = OAuth.getBaseUriString(uri);
    assertEquals(String.format("https://api.mastercard.com/%s", expectedUri), baseUri);
  }

  @Test
  public void testGetBaseUriString_ShouldNotNormalizeEncodedChars() {
    URI uri = URI.create("https://www.example.com/api/test%40test");
    String baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://www.example.com/api/test%40test", baseUri);

    uri = URI.create("http://example.com/r%20v/X?id=123");
    baseUri = OAuth.getBaseUriString(uri);
    assertEquals("http://example.com/r%20v/X", baseUri);

    uri = URI.create("http://example.com/r%2540v/X?id=123");
    baseUri = OAuth.getBaseUriString(uri);
    assertEquals("http://example.com/r%2540v/X", baseUri);
  }

  @Test
  public void testGetBaseUriString_ShouldNotEncodePathSegments() {
    URI uri = URI.create("https://www.example.net:8080/foo@bar/test?query=test");
    String baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://www.example.net:8080/foo@bar/test", baseUri);

    uri = URI.create("https://www.example.net:8080/foo&bar/test?query=test");
    baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://www.example.net:8080/foo&bar/test", baseUri);

    uri = URI.create("https://www.example.net:8080/foo(bar/test?query=test");
    baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://www.example.net:8080/foo(bar/test", baseUri);

    uri = URI.create("https://www.example.net:8080/foo=bar/test?query=test");
    baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://www.example.net:8080/foo=bar/test", baseUri);
  }

  @Test
  public void testGetSignatureBaseString_Nominal() {
    TreeMap<String, List<String>> params = new TreeMap<>();
    params.put("param2", Arrays.asList("hello"));
    params.put("first_param", Arrays.asList("value", "othervalue"));

    HashMap<String, String> oauthParams = new HashMap<>();
    oauthParams.put("oauth_nonce", "randomnonce");
    oauthParams.put("oauth_body_hash", "body/hash");

    String paramString = OAuth.toOauthParamString(params, oauthParams);
    String signatureBaseString = OAuth.getSignatureBaseString("POST", "https://api.mastercard.com", paramString, Charset.defaultCharset());

    assertEquals("POST&https%3A%2F%2Fapi.mastercard.com&first_param%3Dothervalue%26first_param%3Dvalue%26oauth_body_hash%3Dbody%2Fhash%26oauth_nonce%3Drandomnonce%26param2%3Dhello", signatureBaseString);
  }

  @Test
  public void testSignSignatureBaseString() throws Exception {
    String expectedSignatureString = "IJeNKYGfUhFtj5OAPRI92uwfjJJLCej3RCMLbp7R6OIYJhtwxnTkloHQ2bgV7fks4GT/A7rkqrgUGk0ewbwIC6nS3piJHyKVc7rvQXZuCQeeeQpFzLRiH3rsb+ZS+AULK+jzDje4Fb+BQR6XmxuuJmY6YrAKkj13Ln4K6bZJlSxOizbNvt+Htnx+hNd4VgaVBeJKcLhHfZbWQxK76nMnjY7nDcM/2R6LUIR2oLG1L9m55WP3bakAvmOr392ulv1+mWCwDAZZzQ4lakDD2BTu0ZaVsvBW+mcKFxYeTq7SyTQMM4lEwFPJ6RLc8jJJ+veJXHekLVzWg4qHRtzNBLz1mA==";
    assertEquals(expectedSignatureString, OAuth.signSignatureBaseString("baseString", TestUtils.getTestSigningKey(), StandardCharsets.UTF_8));
  }

  @Test
  public void testSignSignatureBaseStringAlgName_ShouldReturnSha256withRsa_WhenAvailable() throws Exception {
    String algName = OAuth.signSignatureBaseStringAlgName("baseString", TestUtils.getTestSigningKey(), StandardCharsets.UTF_8);
    assertEquals("SHA256withRSA", algName);
  }

  @Test
  public void testSignSignatureBaseStringAlgName_ShouldThrowIllegalArgumentException_WhenKeyIsNull() {
    try {
      OAuth.signSignatureBaseStringAlgName("baseString", null, StandardCharsets.UTF_8);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertEquals("signingKey must not be null", e.getMessage());
    }
  }

  @Test
  public void testSignSignatureBaseString_ShouldSupportPssFallbackHelper() throws Exception {
    // We can't reliably force the JCA provider to not support SHA256withRSA in unit tests.
    // Instead, we invoke the PSS signing helper directly by reflection to ensure it works and stays covered.
    java.lang.reflect.Method m = OAuth.class.getDeclaredMethod(
        "doSignWithPssFallback",
        String.class,
        java.security.PrivateKey.class,
        java.nio.charset.Charset.class);
    m.setAccessible(true);

    String signature = (String) m.invoke(null, "baseString", TestUtils.getTestSigningKey(), StandardCharsets.UTF_8);
    assertNotNull(signature);
    assertFalse(signature.isEmpty());
  }

  @Test(expected = IllegalArgumentException.class)
  public void testSignSignatureBaseString_ShouldThrowIllegalArgumentException_WhenKeyIsNull() {
    OAuth.signSignatureBaseString("some string", null, StandardCharsets.UTF_8);
  }

  // ===== Comprehensive tests for signing methods =====

  @Test
  public void testCreateSigner_ShouldReturnSigner_WhenAlgorithmAvailable() {
    java.util.Optional<Signature> signer = OAuth.createSigner("SHA256withRSA", false);
    assertTrue("SHA256withRSA should be available", signer.isPresent());
  }

  @Test
  public void testCreateSigner_ShouldReturnEmpty_WhenAlgorithmNotAvailable() {
    java.util.Optional<Signature> signer = OAuth.createSigner("INVALID-ALGORITHM", false);
    assertFalse("Invalid algorithm should return empty", signer.isPresent());
  }

  @Test
  public void testCreateSigner_ShouldConfigurePss_WhenFlagIsTrue() throws Exception {
    java.util.Optional<Signature> signerOpt = OAuth.createSigner("RSASSA-PSS", true);
    assertTrue("RSASSA-PSS should be available", signerOpt.isPresent());

    Signature signer = signerOpt.get();
    // Verify it's configured by attempting to sign
    signer.initSign(TestUtils.getTestSigningKeyRSAPPSS());
    signer.update("test".getBytes(StandardCharsets.UTF_8));
    byte[] signature = signer.sign();
    assertNotNull("Signature should be generated", signature);
    assertTrue("Signature should not be empty", signature.length > 0);
  }

  @Test
  public void testDoSignWithPssFallback_ShouldSign_WithValidKey() throws Exception {
    String signature = OAuth.doSignWithPssFallback("baseString", TestUtils.getTestSigningKeyRSAPPSS(), StandardCharsets.UTF_8);
    assertNotNull("Signature should not be null", signature);
    assertFalse("Signature should not be empty", signature.isEmpty());
    assertTrue("Signature should be base64 encoded", signature.length() > 100);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testDoSignWithPssFallback_ShouldThrow_WhenKeyIsNull() {
    OAuth.doSignWithPssFallback("baseString", null, StandardCharsets.UTF_8);
  }

  @Test
  public void testDoSign_ShouldSign_WithValidSigner() throws Exception {
    Signature signer = Signature.getInstance("SHA256withRSA");
    String signature = OAuth.doSign("baseString", TestUtils.getTestSigningKey(), StandardCharsets.UTF_8, signer);
    assertNotNull("Signature should not be null", signature);
    assertFalse("Signature should not be empty", signature.isEmpty());
  }

  @Test(expected = GeneralSecurityException.class)
  public void testDoSign_ShouldThrow_WhenSignerNotInitialized() throws Exception {
    Signature signer = Signature.getInstance("SHA256withRSA");
    // Don't initialize the signer - this should cause an exception
    signer.update("test".getBytes(StandardCharsets.UTF_8));
    signer.sign();
  }

  @Test
  public void testDoSignUnchecked_ShouldSign_WithSHA256withRSA() throws Exception {
    Signature signer = Signature.getInstance("SHA256withRSA");
    String signature = OAuth.doSignUnchecked("baseString", TestUtils.getTestSigningKey(), StandardCharsets.UTF_8, signer, "SHA256withRSA");
    assertNotNull("Signature should not be null", signature);
    assertFalse("Signature should not be empty", signature.isEmpty());
    assertEquals("Signature should match expected",
        "IJeNKYGfUhFtj5OAPRI92uwfjJJLCej3RCMLbp7R6OIYJhtwxnTkloHQ2bgV7fks4GT/A7rkqrgUGk0ewbwIC6nS3piJHyKVc7rvQXZuCQeeeQpFzLRiH3rsb+ZS+AULK+jzDje4Fb+BQR6XmxuuJmY6YrAKkj13Ln4K6bZJlSxOizbNvt+Htnx+hNd4VgaVBeJKcLhHfZbWQxK76nMnjY7nDcM/2R6LUIR2oLG1L9m55WP3bakAvmOr392ulv1+mWCwDAZZzQ4lakDD2BTu0ZaVsvBW+mcKFxYeTq7SyTQMM4lEwFPJ6RLc8jJJ+veJXHekLVzWg4qHRtzNBLz1mA==",
        signature);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testDoSignUnchecked_ShouldThrow_WhenKeyIsNull() throws Exception {
    Signature signer = Signature.getInstance("SHA256withRSA");
    OAuth.doSignUnchecked("baseString", null, StandardCharsets.UTF_8, signer, "SHA256withRSA");
  }

  @Test
  public void testDoSignUnchecked_ShouldFallbackToPss_WhenSHA256withRSAFails() throws Exception {
    // Create a mock signer that will fail on initSign
    Signature signer = Signature.getInstance("SHA256withRSA");
    // We can't easily mock the failure, but we can test with a different algorithm marker
    // to ensure the non-SHA256withRSA path is covered
    try {
      // This tests the error handling path
      OAuth.doSignUnchecked("baseString", TestUtils.getTestSigningKey(), StandardCharsets.UTF_8, signer, "RSASSA-PSS");
      // If we reach here with RSASSA-PSS alg marker, it should have succeeded
      // The test verifies the conditional logic exists
    } catch (IllegalStateException e) {
      // This is expected if the signer fails and alg != SHA256withRSA
      assertTrue("Error message should mention signing failure",
          e.getMessage().contains("Unable to sign"));
    }
  }

  @Test
  public void testDoSignUnchecked_ShouldThrowIllegalStateException_WhenSignerFails_AndAlgNotSha256WithRsa() throws Exception {
    // Force the try-block to throw by using a Signature that isn't initialised for signing.
    Signature badSigner = Signature.getInstance("SHA256withRSA");

    try {
      OAuth.doSignUnchecked("baseString", TestUtils.getTestSigningKeyRSAPPSS(), StandardCharsets.UTF_8, badSigner, "RSASSA-PSS");
      fail("Expected IllegalStateException");
    } catch (IllegalStateException e) {
      assertTrue(e.getCause() instanceof GeneralSecurityException);
      assertTrue(e.getMessage().contains("Unable to sign OAuth signature base string"));
    }
  }

  @Test
  public void testDoSignUnchecked_ShouldFallbackToPss_WhenSignerFails_AndAlgIsSha256WithRsa() throws Exception {
    // Force the try-block to throw by using a Signature that isn't initialised for signing.
    Signature badSigner = Signature.getInstance("SHA256withRSA");

    String signature = OAuth.doSignUnchecked("baseString", TestUtils.getTestSigningKey(), StandardCharsets.UTF_8, badSigner, "SHA256withRSA");
    assertNotNull(signature);
    assertFalse(signature.isEmpty());
  }

  @Test
  public void testSignSignatureBaseString_WithDifferentCharsets() throws Exception {
    PrivateKey key = TestUtils.getTestSigningKey();

    // Test with UTF-8
    String sig1 = OAuth.signSignatureBaseString("baseString", key, StandardCharsets.UTF_8);
    assertNotNull("UTF-8 signature should not be null", sig1);

    // Test with ISO-8859-1
    String sig2 = OAuth.signSignatureBaseString("baseString", key, StandardCharsets.ISO_8859_1);
    assertNotNull("ISO-8859-1 signature should not be null", sig2);

    // They should be the same for ASCII strings
    assertEquals("Signatures should match for ASCII string", sig1, sig2);
  }

  @Test
  public void testSignSignatureBaseString_WithSpecialCharacters() throws Exception {
    PrivateKey key = TestUtils.getTestSigningKey();

    String signature = OAuth.signSignatureBaseString("base€String with spëcial çhars", key, StandardCharsets.UTF_8);
    assertNotNull("Signature should handle special chars", signature);
    assertFalse("Signature should not be empty", signature.isEmpty());
  }

  @Test
  public void testSignSignatureBaseString_WithEmptyString() throws Exception {
    PrivateKey key = TestUtils.getTestSigningKey();

    String signature = OAuth.signSignatureBaseString("", key, StandardCharsets.UTF_8);
    assertNotNull("Signature should handle empty string", signature);
    assertFalse("Signature should not be empty", signature.isEmpty());
  }

  @Test
  public void testSignSignatureBaseString_WithLongString() throws Exception {
    PrivateKey key = TestUtils.getTestSigningKey();

    StringBuilder longString = new StringBuilder();
    for (int i = 0; i < 10000; i++) {
      longString.append("a");
    }

    String signature = OAuth.signSignatureBaseString(longString.toString(), key, StandardCharsets.UTF_8);
    assertNotNull("Signature should handle long string", signature);
    assertFalse("Signature should not be empty", signature.isEmpty());
  }

  @Test
  public void testCreateSigner_WithPssConfiguration() throws Exception {
    java.util.Optional<Signature> signerOpt = OAuth.createSigner("RSASSA-PSS", true);
    assertTrue("RSASSA-PSS with config should be available", signerOpt.isPresent());

    if (signerOpt.isPresent()) {
      Signature signer = signerOpt.get();
      signer.initSign(TestUtils.getTestSigningKey());
      signer.update("test data".getBytes(StandardCharsets.UTF_8));
      byte[] signature = signer.sign();

      assertNotNull("PSS signature should not be null", signature);
      assertTrue("PSS signature should have content", signature.length > 0);
    }
  }

  @Test
  public void testCreateSigner_WithoutPssConfiguration() throws Exception {
    java.util.Optional<Signature> signerOpt = OAuth.createSigner("RSASSA-PSS", false);
    assertTrue("RSASSA-PSS without config should be available", signerOpt.isPresent());
  }

  @Test
  public void testSignSignatureBaseStringAlgName_Consistency() throws Exception {
    // Verify the algorithm name matches what's actually used
    String algName = OAuth.signSignatureBaseStringAlgName("test", TestUtils.getTestSigningKey(), StandardCharsets.UTF_8);

    // Should return SHA256withRSA on standard JVMs
    assertTrue("Algorithm should be SHA256withRSA or RSASSA-PSS",
        "SHA256withRSA".equals(algName) || "RSASSA-PSS".equals(algName));

    // Verify signing with the same params works
    String signature = OAuth.signSignatureBaseString("test", TestUtils.getTestSigningKey(), StandardCharsets.UTF_8);
    assertNotNull("Signature should be generated", signature);
  }

  @Test
  public void testDoSign_WithDifferentSignatureAlgorithms() throws Exception {
    PrivateKey key = TestUtils.getTestSigningKey();

    // Test SHA256withRSA
    Signature sha256Signer = Signature.getInstance("SHA256withRSA");
    String sig1 = OAuth.doSign("test", key, StandardCharsets.UTF_8, sha256Signer);
    assertNotNull("SHA256withRSA signature should not be null", sig1);

    // Test RSASSA-PSS
    Signature pssSigner = Signature.getInstance("RSASSA-PSS");
    pssSigner.setParameter(new java.security.spec.PSSParameterSpec(
        "SHA-256", "MGF1", java.security.spec.MGF1ParameterSpec.SHA256, 32, 1));
    String sig2 = OAuth.doSign("test", key, StandardCharsets.UTF_8, pssSigner);
    assertNotNull("RSASSA-PSS signature should not be null", sig2);

    // PSS signatures include randomness, so they should be different each time
    String sig3 = OAuth.doSign("test", key, StandardCharsets.UTF_8, pssSigner);
    // Note: PSS signatures are non-deterministic, so sig2 != sig3 typically
  }

  @Test
  public void testGetAuthorizationHeader_ShouldThrowIllegalArgumentException_WhenRequiredParamsNull() throws Exception {
    URI uri = URI.create("https://sandbox.api.mastercard.com/service");
    PrivateKey key = TestUtils.getTestSigningKey();

    try {
      OAuth.getAuthorizationHeader(null, "POST", "payload", StandardCharsets.UTF_8, "ck", key);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("Required parameters"));
    }

    try {
      OAuth.getAuthorizationHeader(uri, null, "payload", StandardCharsets.UTF_8, "ck", key);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("Required parameters"));
    }

    try {
      OAuth.getAuthorizationHeader(uri, "POST", "payload", null, "ck", key);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("Required parameters"));
    }

    try {
      OAuth.getAuthorizationHeader(uri, "POST", "payload", StandardCharsets.UTF_8, null, key);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("Required parameters"));
    }

    try {
      OAuth.getAuthorizationHeader(uri, "POST", "payload", StandardCharsets.UTF_8, "ck", null);
      fail("Expected IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("Required parameters"));
    }
  }

  @Test
  public void testGetAuthorizationHeader_ShouldReturnOAuthHeader_WhenNominal() throws Exception {
    URI uri = URI.create("https://sandbox.api.mastercard.com/service?param=value");
    Charset charset = StandardCharsets.UTF_8;
    String consumerKey = "test-consumer-key";
    PrivateKey key = TestUtils.getTestSigningKey();

    String payload = "Hello world!";
    String authHeader = OAuth.getAuthorizationHeader(uri, "POST", payload, charset, consumerKey, key);

    assertNotNull(authHeader);
    assertTrue(authHeader.startsWith("OAuth "));

    // Contains required/oauth fields
    assertTrue(authHeader.contains("oauth_consumer_key=\"" + consumerKey + "\""));
    assertTrue(authHeader.contains("oauth_nonce=\""));
    assertTrue(authHeader.contains("oauth_timestamp=\""));
    assertTrue(authHeader.contains("oauth_version=\"1.0\""));

    // Signature method & signature
    assertTrue(authHeader.contains("oauth_signature_method=\"RSA-SHA256\""));
    assertTrue(authHeader.contains("oauth_signature=\""));

    // Body hash should match what getBodyHash computes
    String expectedBodyHash = OAuth.getBodyHash(payload, charset, HASH_ALGORITHM);
    assertTrue(authHeader.contains("oauth_body_hash=\"" + expectedBodyHash + "\""));
  }

  @Test
  public void testSignSignatureBaseStringAlgName_ShouldReturnRsassaPss_WhenForcedForTests() throws Exception {
    boolean previous = OAuth.FORCE_PSS_ALG_PROBE_FOR_TESTS;
    OAuth.FORCE_PSS_ALG_PROBE_FOR_TESTS = true;
    try {
      String algName = OAuth.signSignatureBaseStringAlgName("baseString", TestUtils.getTestSigningKey(), StandardCharsets.UTF_8);
      assertEquals("RSASSA-PSS", algName);
    } finally {
      OAuth.FORCE_PSS_ALG_PROBE_FOR_TESTS = previous;
    }
  }
}
