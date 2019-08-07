package com.mastercard.developer.signers;

import com.mastercard.developer.test.TestUtils;

import org.springframework.http.HttpMessage;
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
	
	private static final HttpMethod method = HttpMethod.POST;
	private static final String body = "{\"foo\":\"bar\"}";
	private static final String consumerKey = "Some key";
	
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
			public HttpMethod getMethod(){
				return method;
			}
			public String getMethodValue(){
				return getMethod().toString();
			}
			public URI getURI(){
				return uri;
			}
			public HttpHeaders getHeaders(){
				return headers;
			}
		};
	}
	
	@Test
	public void testSign_ShouldAddOAuth1HeaderToPostRequest() throws Exception {
	
		// WHEN
		SpringHttpRequestSigner instanceUnderTest = new SpringHttpRequestSigner(consumerKey, signingKey);
		instanceUnderTest.sign(request, body.getBytes());
		
		// THEN
		String authorizationHeaderValue = headers.getFirst(HttpHeaders.AUTHORIZATION);
		Assert.assertNotNull(authorizationHeaderValue);
	}
	
	@Test
	public void testSign_ShouldAddOAuth1HeaderToPostRequestWithCharset() throws Exception {
	
		// GIVEN
		headers.setContentType(MediaType.APPLICATION_JSON_UTF8);
		
		// WHEN
		SpringHttpRequestSigner instanceUnderTest = new SpringHttpRequestSigner(consumerKey, signingKey);
		instanceUnderTest.sign(request, body.getBytes());
		
		// THEN
		String authorizationHeaderValue = headers.getFirst(HttpHeaders.AUTHORIZATION);
		Assert.assertNotNull(authorizationHeaderValue);
	}
	
	@Test
	public void testSign_ShouldAddOAuth1HeaderToPostRequestWithInvalidCharset() throws Exception {
	
		// GIVEN
		headers.setContentType(MediaType.APPLICATION_PDF);
		
		// WHEN
		SpringHttpRequestSigner instanceUnderTest = new SpringHttpRequestSigner(consumerKey, signingKey);
		instanceUnderTest.sign(request, body.getBytes());
		
		// THEN
		String authorizationHeaderValue = headers.getFirst(HttpHeaders.AUTHORIZATION);
		Assert.assertNotNull(authorizationHeaderValue);
	}

}
