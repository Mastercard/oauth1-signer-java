package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;
import com.mastercard.developer.oauth.SignatureMethod;
import com.mastercard.developer.test.TestUtils;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import org.springframework.http.HttpRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;

import java.net.URI;
import java.nio.charset.Charset;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.PrivateKey;
import java.util.Map;

import static com.mastercard.developer.test.TestUtils.UTF8_CHARSET;

public class SpringHttpRequestSignerTest {
	
	private static final HttpMethod POST_METHOD = HttpMethod.POST;
	private static final HttpMethod GET_METHOD = HttpMethod.GET;
	private static final String DEFAULT_BODY = "{\"foo\":\"bar\"}";
	private static final String DEFAULT_CONSUMER_KEY = "Some key";
	
	private PrivateKey signingKey;
	private URI uri;
	private HttpHeaders headers;
	private HttpRequest request;
	
	@Before 
	public void initialize() throws Exception {
	
		signingKey = TestUtils.getTestSigningKey();
		uri = new URI("https://api.mastercard.com/service");
		headers = new HttpHeaders();
		request = new HttpRequest() {
			@Override
			public HttpMethod getMethod(){
				return POST_METHOD;
			}
			@Override
			public URI getURI(){
				return uri;
			}

			@Override
			public Map<String, Object> getAttributes() {
				return Map.of();
			}

			@Override
			public HttpHeaders getHeaders(){
				return headers;
			}
		};
	}
	
	@Test
	public void testSignShouldAddOAuth1HeaderToPostRequest() {

		// WHEN
		SpringHttpRequestSigner instanceUnderTest = new SpringHttpRequestSigner(DEFAULT_CONSUMER_KEY, signingKey);
		instanceUnderTest.sign(request, DEFAULT_BODY.getBytes());

		// THEN
		String authorizationHeaderValue = headers.getFirst(HttpHeaders.AUTHORIZATION);
		Assert.assertNotNull(authorizationHeaderValue);
	}
	
	@Test
	public void testSignShouldAddOAuth1HeaderToPostRequestWithCharset() {
	
		// GIVEN
		headers.setContentType(MediaType.APPLICATION_JSON);
		
		// WHEN
		SpringHttpRequestSigner instanceUnderTest = new SpringHttpRequestSigner(DEFAULT_CONSUMER_KEY, signingKey);
		instanceUnderTest.sign(request, DEFAULT_BODY.getBytes());
		
		// THEN
		String authorizationHeaderValue = headers.getFirst(HttpHeaders.AUTHORIZATION);
		Assert.assertNotNull(authorizationHeaderValue);
	}
	
	@Test
	public void testSignShouldAddOAuth1HeaderToPostRequestWithInvalidCharset() {
	
		// GIVEN
		headers.setContentType(MediaType.APPLICATION_PDF);
		
		// WHEN
		SpringHttpRequestSigner instanceUnderTest = new SpringHttpRequestSigner(DEFAULT_CONSUMER_KEY, signingKey);
		instanceUnderTest.sign(request, DEFAULT_BODY.getBytes());
		
		// THEN
		String authorizationHeaderValue = headers.getFirst(HttpHeaders.AUTHORIZATION);
		Assert.assertNotNull(authorizationHeaderValue);
	}

	@Test
	public void testSignShouldAddOAuth1HeaderToGetRequestNullBody() {
	
		// GIVEN
		request = new HttpRequest() {
			@Override
			public HttpMethod getMethod(){
				return GET_METHOD;
			}
			@Override
			public URI getURI(){
				return uri;
			}

			@Override
			public Map<String, Object> getAttributes() {
				return Map.of();
			}

			@Override
			public HttpHeaders getHeaders(){
				return headers;
			}
		};

		// WHEN
		SpringHttpRequestSigner instanceUnderTest = new SpringHttpRequestSigner(DEFAULT_CONSUMER_KEY, signingKey);
		instanceUnderTest.sign(request, null);
		
		// THEN
		String authorizationHeaderValue = headers.getFirst(HttpHeaders.AUTHORIZATION);
		Assert.assertNotNull(authorizationHeaderValue);
	}

	@Test
	public void testSignShouldAddOAuth1HeaderToGetRequestEmptyBody() {
	
		// GIVEN
		request = new HttpRequest() {
			@Override
			public HttpMethod getMethod(){
				return GET_METHOD;
			}
			@Override
			public URI getURI(){
				return uri;
			}

			@Override
			public Map<String, Object> getAttributes() {
				return Map.of();
			}

			@Override
			public HttpHeaders getHeaders(){
				return headers;
			}
		};

		// WHEN
		SpringHttpRequestSigner instanceUnderTest = new SpringHttpRequestSigner(DEFAULT_CONSUMER_KEY, signingKey);
		instanceUnderTest.sign(request, "".getBytes());
		
		// THEN
		String authorizationHeaderValue = headers.getFirst(HttpHeaders.AUTHORIZATION);
		Assert.assertNotNull(authorizationHeaderValue);
	}

	@ParameterizedTest
	@EnumSource(SignatureMethod.class)
	public void testSignShouldInvokeSigningAsExpected(SignatureMethod signatureMethod) throws Exception {

		// GIVEN
		PrivateKey signingKey = TestUtils.getTestSigningKey();
		String consumerKey = DEFAULT_CONSUMER_KEY;
		Charset charset = UTF8_CHARSET;
		String payload = DEFAULT_BODY;

		HttpHeaders localHeaders = new HttpHeaders();
		localHeaders.setContentType(new MediaType("application", "json", charset));
		URI expectedUri = new URI("https://api.mastercard.com/service");

		HttpRequest localRequest = new HttpRequest() {
			@Override
			public HttpMethod getMethod() {
				return POST_METHOD;
			}

			@Override
			public URI getURI() {
				return expectedUri;
			}

			@Override
			public Map<String, Object> getAttributes() {
				return Map.of();
			}

			@Override
			public HttpHeaders getHeaders() {
				return localHeaders;
			}
		};

		try (MockedStatic<OAuth> oauthMock = Mockito.mockStatic(OAuth.class)) {
			oauthMock.when(() -> OAuth.getAuthorizationHeader(
					expectedUri,
					"POST",
					payload,
					charset,
					consumerKey,
					signingKey,
					signatureMethod
			)).thenReturn("OAuth header");

			SpringHttpRequestSigner instanceUnderTest = new SpringHttpRequestSigner(consumerKey, signingKey, signatureMethod);

			// WHEN
			instanceUnderTest.sign(localRequest, payload.getBytes(charset));

			// THEN
			oauthMock.verify(() -> OAuth.getAuthorizationHeader(
					expectedUri,
					"POST",
					payload,
					charset,
					consumerKey,
					signingKey,
					signatureMethod
			));
		}
	}
}
