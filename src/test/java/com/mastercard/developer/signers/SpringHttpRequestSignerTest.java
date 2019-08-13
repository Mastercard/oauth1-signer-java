package com.mastercard.developer.signers;

import com.mastercard.developer.test.TestUtils;

import org.springframework.http.HttpRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;

import java.net.URI;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.PrivateKey;

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
			public String getMethodValue(){
				return getMethod().toString();
			}
			@Override
			public URI getURI(){
				return uri;
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
		headers.setContentType(MediaType.APPLICATION_JSON_UTF8);
		
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
			public String getMethodValue(){
				return getMethod().toString();
			}
			@Override
			public URI getURI(){
				return uri;
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
			public String getMethodValue(){
				return getMethod().toString();
			}
			@Override
			public URI getURI(){
				return uri;
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

}
