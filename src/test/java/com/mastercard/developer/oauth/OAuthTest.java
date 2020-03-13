package com.mastercard.developer.oauth;

import com.mastercard.developer.test.TestUtils;
import org.junit.BeforeClass;
import org.junit.Test;

import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
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
  public void testGetBaseUriString_ShouldNotEncodePathParams() {
    URI uri = URI.create("https://www.example.net:8080/foo@bar/test?query=test");
    String baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://www.example.net:8080/foo@bar/test", baseUri);
  }

  @Test
  public void testGetBaseUriString_ShouldNotDoubleEncodePathParams() {
    URI uri = URI.create("https://www.example.net:8080/foo%40bar/test?query=test");
    String baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://www.example.net:8080/foo%40bar/test", baseUri);
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

  @Test
  public void testGetBaseUriString_ShouldRemoveFragments() {
    URI uri = URI.create("https://api.mastercard.com/test?query=param#fragment");
    String baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://api.mastercard.com/test", baseUri);
  }

  @Test
  public void testGetBaseUriString_ShouldAddTrailingSlash() {
    URI uri = URI.create("https://api.mastercard.com");
    String baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://api.mastercard.com/", baseUri);
  }

  @Test
  public void testGetBaseUriString_ShouldUseLowercaseSchemesAndHosts() {
    URI uri = URI.create("HTTPS://API.MASTERCARD.COM/TEST");
    String baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://api.mastercard.com/TEST", baseUri);
  }

  @Test
  public void testGetBaseUriString_ShouldNotNormalizeEncodedChars() {
    URI uri = URI.create("https://api.mastercard.com/service/api/test%40test");
    String baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://api.mastercard.com/service/api/test%40test", baseUri);

    uri = URI.create("http://example.com/r%20v/X?id=123");
    baseUri = OAuth.getBaseUriString(uri);
    assertEquals("http://example.com/r%20v/X", baseUri);
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

  @Test(expected = IllegalStateException.class)
  public void testSignSignatureBaseString_ShouldThrowIllegalStateException_WhenInvalidKey() {
    OAuth.signSignatureBaseString("some string", null, StandardCharsets.UTF_8);
  }

  @Test
  public void testGetSignatureBaseString_Integrated() {
    Charset charset = Charset.forName("ISO-8859-1");
    String body = "<?xml version=\"1.0\" encoding=\"Windows-1252\"?><ns2:TerminationInquiryRequest xmlns:ns2=\"http://mastercard.com/termination\"><AcquirerId>1996</AcquirerId><TransactionReferenceNumber>1</TransactionReferenceNumber><Merchant><Name>TEST</Name><DoingBusinessAsName>TEST</DoingBusinessAsName><PhoneNumber>5555555555</PhoneNumber><NationalTaxId>1234567890</NationalTaxId><Address><Line1>5555 Test Lane</Line1><City>TEST</City><CountrySubdivision>XX</CountrySubdivision><PostalCode>12345</PostalCode><Country>USA</Country></Address><Principal><FirstName>John</FirstName><LastName>Smith</LastName><NationalId>1234567890</NationalId><PhoneNumber>5555555555</PhoneNumber><Address><Line1>5555 Test Lane</Line1><City>TEST</City><CountrySubdivision>XX</CountrySubdivision><PostalCode>12345</PostalCode><Country>USA</Country></Address><DriversLicense><Number>1234567890</Number><CountrySubdivision>XX</CountrySubdivision></DriversLicense></Principal></Merchant></ns2:TerminationInquiryRequest>";
    String method = "POST";
    URI url = URI.create("https://sandbox.api.mastercard.com/fraud/merchant/v1/termination-inquiry?Format=XML&PageOffset=0&PageLength=10");

    HashMap<String, String> oauthParams = new HashMap<>();
    oauthParams.put("oauth_consumer_key", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    oauthParams.put("oauth_nonce", "1111111111111111111");
    oauthParams.put("oauth_signature_method", "RSA-SHA256");
    oauthParams.put("oauth_timestamp", "1111111111");
    oauthParams.put("oauth_version", "1.0");
    oauthParams.put("oauth_body_hash", OAuth.getBodyHash(body, charset, HASH_ALGORITHM));

    String paramString = OAuth.toOauthParamString(OAuth.extractQueryParams(url, charset), oauthParams);
    String baseString = OAuth.getSignatureBaseString(method, OAuth.getBaseUriString(url), paramString, charset);

    String expected = "POST&https%3A%2F%2Fsandbox.api.mastercard.com%2Ffraud%2Fmerchant%2Fv1%2Ftermination-inquiry&Format%3DXML%26PageLength%3D10%26PageOffset%3D0%26oauth_body_hash%3Dh2Pd7zlzEZjZVIKB4j94UZn%2FxxoR3RoCjYQ9%2FJdadGQ%3D%26oauth_consumer_key%3Dxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx%26oauth_nonce%3D1111111111111111111%26oauth_signature_method%3DRSA-SHA256%26oauth_timestamp%3D1111111111%26oauth_version%3D1.0";
    assertEquals(expected, baseString);
  }

  @Test
  public void testPercentEncode() {
    Charset charset = Charset.defaultCharset();

    assertEquals("Format%3DXML", Util.percentEncode("Format=XML", charset));
    assertEquals("WhqqH%2BTU95VgZMItpdq78BWb4cE%3D", Util.percentEncode("WhqqH+TU95VgZMItpdq78BWb4cE=", charset));
    assertEquals("WhqqH%2BTU95VgZMItpdq78BWb4cE%3D%26o", Util.percentEncode("WhqqH+TU95VgZMItpdq78BWb4cE=&o", charset));
    assertEquals("WhqqH%2BTU95VgZ~Itpdq78BWb4cE%3D%26o", Util.percentEncode("WhqqH+TU95VgZ~Itpdq78BWb4cE=&o", charset)); // Tilde stays unescaped
  }

  @Test
  public void testGetNonce_ShouldBeUniqueAndHaveLengthOf16() {
    String nonce = OAuth.getNonce();
    assertEquals(16, nonce.length());

    final ConcurrentLinkedQueue nonces = new ConcurrentLinkedQueue();
    ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
    int randomNonces = 100000;
    for (int i = 0; i < randomNonces; i++) {
      Runnable worker = new Runnable() {
        @Override
        public void run() {
          nonces.add(OAuth.getNonce());
        }
      };
      executor.execute(worker);
    }
    executor.shutdown();
    while (!executor.isTerminated()) {
    }

    HashSet<String> dupes = new HashSet<>(nonces);
    if (dupes.size() != randomNonces) {
      fail("Expected " + randomNonces + " but got " + dupes.size());
    }
  }
}
