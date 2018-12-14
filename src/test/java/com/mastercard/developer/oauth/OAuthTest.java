package com.mastercard.developer.oauth;

import static com.mastercard.developer.test.TestUtils.UTF8_CHARSET;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.net.URI;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.BeforeClass;
import org.junit.Test;

public class OAuthTest {

  @BeforeClass
  public static void beforeClass() {
    System.setProperty("java.util.logging.config.file", ClassLoader.getSystemResource("logging.properties").getPath());
  }

  @Test
  public void queryParser() throws Exception {
    URI uri = new URI("https://sandbox.api.mastercard.com/audiences/v1/getcountries?offset=0&offset=1&length=10&empty&odd=");
    Map<String, List<String>> queryParams = OAuth.extractQueryParams(uri, UTF8_CHARSET);

    assertEquals(queryParams.toString(), 4, queryParams.size());
    assertArrayEquals(new String[]{"10"}, queryParams.get("length").toArray());
    assertArrayEquals(new String[]{"0", "1"}, queryParams.get("offset").toArray());
    assertArrayEquals(new String[]{""}, queryParams.get("empty").toArray());
    assertArrayEquals(new String[]{""}, queryParams.get("odd").toArray());
  }

  @Test
  public void queryParserEncoding() throws Exception {
    URI uri = new URI("https://sandbox.api.mastercard.com?param1=plus+value&param2=colon:value");
    Map<String, List<String>> queryParams = OAuth.extractQueryParams(uri, UTF8_CHARSET);

    assertEquals(queryParams.toString(), 2, queryParams.size());
    assertArrayEquals(new String[]{"plus%2Bvalue"}, queryParams.get("param1").toArray());
    assertArrayEquals(new String[]{"colon%3Avalue"}, queryParams.get("param2").toArray());
  }

  @Test
  public void queryParserNotEncodedParams() throws Exception {
    URI uri = new URI("https", "api.mastercard.com", "/audiences", "param1=plus+value&param2=colon:value&param3=a space~", null);
    Map<String, List<String>> queryParams = OAuth.extractQueryParams(uri, UTF8_CHARSET);

    assertEquals(queryParams.toString(), 3, queryParams.size());
    assertArrayEquals(new String[]{"plus%2Bvalue"}, queryParams.get("param1").toArray());
    assertArrayEquals(new String[]{"colon%3Avalue"}, queryParams.get("param2").toArray());
    assertArrayEquals(new String[]{"a%20space~"}, queryParams.get("param3").toArray());
  }

  @Test
  public void nonceUniqueness() {
    String nonce = OAuth.getNonce();
    assertEquals(32, nonce.length());

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

    HashSet<String> dupes = new HashSet<String>(nonces);
    if (dupes.size() != randomNonces) {
      fail("Expected " + randomNonces + " but got " + dupes.size());
    }
  }

  @Test
  public void oauthParamsString() {
    TreeMap<String, List<String>> params = new TreeMap<String, List<String>>();
    params.put("param2", Arrays.asList("hello"));
    params.put("first_param", Arrays.asList("value", "othervalue"));
    params.put("param3", Arrays.asList("world"));

    HashMap<String, String> oauthParams = new HashMap<String, String>();
    oauthParams.put("oauth_nonce", "randomnonce");
    oauthParams.put("oauth_body_hash", "body/hash");

    String paramString = OAuth.toOauthParamString(params, oauthParams);

    assertEquals("first_param=othervalue&first_param=value&oauth_body_hash=body/hash&oauth_nonce=randomnonce&param2=hello&param3=world", paramString);
  }

  @Test
  public void signatureBaseString() {
    TreeMap<String, List<String>> params = new TreeMap<String, List<String>>();
    params.put("param2", Arrays.asList("hello"));
    params.put("first_param", Arrays.asList("value", "othervalue"));

    HashMap<String, String> oauthParams = new HashMap<String, String>();
    oauthParams.put("oauth_nonce", "randomnonce");
    oauthParams.put("oauth_body_hash", "body/hash");

    String paramString = OAuth.toOauthParamString(params, oauthParams);

    String signatureBaseString = OAuth.getSignatureBaseString("POST", "https://api.mastercard.com", paramString, Charset.defaultCharset());

    assertEquals(
        "POST&https%3A%2F%2Fapi.mastercard.com&first_param%3Dothervalue%26first_param%3Dvalue%26oauth_body_hash%3Dbody%2Fhash%26oauth_nonce%3Drandomnonce%26param2%3Dhello",
        signatureBaseString);
  }

  @Test
  public void signatureBaseString2() {
    Charset charset = Charset.forName("ISO-8859-1");
    String body = "<?xml version=\"1.0\" encoding=\"Windows-1252\"?><ns2:TerminationInquiryRequest xmlns:ns2=\"http://mastercard.com/termination\"><AcquirerId>1996</AcquirerId><TransactionReferenceNumber>1</TransactionReferenceNumber><Merchant><Name>TEST</Name><DoingBusinessAsName>TEST</DoingBusinessAsName><PhoneNumber>5555555555</PhoneNumber><NationalTaxId>1234567890</NationalTaxId><Address><Line1>5555 Test Lane</Line1><City>TEST</City><CountrySubdivision>XX</CountrySubdivision><PostalCode>12345</PostalCode><Country>USA</Country></Address><Principal><FirstName>John</FirstName><LastName>Smith</LastName><NationalId>1234567890</NationalId><PhoneNumber>5555555555</PhoneNumber><Address><Line1>5555 Test Lane</Line1><City>TEST</City><CountrySubdivision>XX</CountrySubdivision><PostalCode>12345</PostalCode><Country>USA</Country></Address><DriversLicense><Number>1234567890</Number><CountrySubdivision>XX</CountrySubdivision></DriversLicense></Principal></Merchant></ns2:TerminationInquiryRequest>";
    String method = "POST";
    URI url = URI.create("https://sandbox.api.mastercard.com/fraud/merchant/v1/termination-inquiry?Format=XML&PageOffset=0&PageLength=10");

    HashMap<String, String> oauthParams = new HashMap<String, String>();
    oauthParams.put("oauth_consumer_key", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    oauthParams.put("oauth_nonce", "1111111111111111111");
    oauthParams.put("oauth_signature_method", "RSA-SHA256");
    oauthParams.put("oauth_timestamp", "1111111111");
    oauthParams.put("oauth_version", "1.0");
    oauthParams.put("oauth_body_hash", OAuth.getBodyHash(body, charset));

    String paramString = OAuth.toOauthParamString(OAuth.extractQueryParams(url, charset), oauthParams);
    String baseString = OAuth.getSignatureBaseString(method, OAuth.getBaseUriString(url), paramString, charset);

    String expected = "POST&https%3A%2F%2Fsandbox.api.mastercard.com%2Ffraud%2Fmerchant%2Fv1%2Ftermination-inquiry&Format%3DXML%26PageLength%3D10%26PageOffset%3D0%26oauth_body_hash%3Dh2Pd7zlzEZjZVIKB4j94UZn%2FxxoR3RoCjYQ9%2FJdadGQ%3D%26oauth_consumer_key%3Dxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx%26oauth_nonce%3D1111111111111111111%26oauth_signature_method%3DRSA-SHA256%26oauth_timestamp%3D1111111111%26oauth_version%3D1.0";
    assertEquals(expected, baseString);
  }

  @Test
  public void urlNormalizationRedundantPorts() throws Exception {
    URI uri = new URI("https://api.mastercard.com:443/test?query=param");
    String baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://api.mastercard.com/test", baseUri);

    uri = new URI("http://api.mastercard.com:80/test");
    baseUri = OAuth.getBaseUriString(uri);
    assertEquals("http://api.mastercard.com/test", baseUri);

    uri = new URI("https://api.mastercard.com:17443/test?query=param");
    baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://api.mastercard.com:17443/test", baseUri);
  }

  @Test
  public void urlNormalizationRemoveFragment() throws Exception {
    URI uri = new URI("https://api.mastercard.com/test?query=param#fragment");
    String baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://api.mastercard.com/test", baseUri);
  }

  @Test
  public void urlNormalizationAddTrailingSlash() throws Exception {
    URI uri = new URI("https://api.mastercard.com");
    String baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://api.mastercard.com/", baseUri);
  }

  @Test
  public void urlNormalizationLowercaseSchemeAndHost() throws Exception {
    URI uri = new URI("HTTPS://API.mastercard.com/test");
    String baseUri = OAuth.getBaseUriString(uri);
    assertEquals("https://api.mastercard.com/test", baseUri);
  }

  @Test
  public void bodyHash() {
    String bodyHash = OAuth.getBodyHash(OAuth.EMPTY_STRING, UTF8_CHARSET);
    assertThat(bodyHash).isEqualTo("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");

    bodyHash = OAuth.getBodyHash("{\"foõ\":\"bar\"}", UTF8_CHARSET);
    assertThat(bodyHash).isEqualTo("+Z+PWW2TJDnPvRcTgol+nKO3LT7xm8smnsg+//XMIyI=");
  }

  @Test
  public void urlEncodeTests() {
    Charset charset = Charset.defaultCharset();

    assertEquals("Format%3DXML", Util.percentEncode("Format=XML", charset));
    assertEquals("WhqqH%2BTU95VgZMItpdq78BWb4cE%3D", Util.percentEncode("WhqqH+TU95VgZMItpdq78BWb4cE=", charset));
    assertEquals("WhqqH%2BTU95VgZMItpdq78BWb4cE%3D%26o", Util.percentEncode("WhqqH+TU95VgZMItpdq78BWb4cE=&o", charset));
    // Tilde stays unescaped
    assertEquals("WhqqH%2BTU95VgZ~Itpdq78BWb4cE%3D%26o", Util.percentEncode("WhqqH+TU95VgZ~Itpdq78BWb4cE=&o", charset));
  }
}
