package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;

import java.nio.charset.Charset;
import java.security.PrivateKey;

import com.mastercard.developer.oauth.SignatureMethod;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

/**
 * Utility class for signing Spring RestTemplate requests.
 */
public final class SpringHttpRequestSigner extends AbstractSigner {
    
    public SpringHttpRequestSigner(String consumerKey, PrivateKey signingKey) {
        super(consumerKey, signingKey);
    }

    public SpringHttpRequestSigner(String consumerKey, PrivateKey signingKey, SignatureMethod signatureMethod) {
        super(consumerKey, signingKey, signatureMethod);
    }
    
    public void sign(HttpRequest request, byte[] bytes) {
        HttpMethod method = request.getMethod();
        HttpHeaders headers = request.getHeaders();
        Charset charset = getCharset(headers);
        String payload = (null == bytes ? null : new String(bytes, charset));
        String authHeader = OAuth.getAuthorizationHeader(request.getURI(), method.toString(), payload, charset, consumerKey, signingKey, signatureMethod);
        headers.add(OAuth.AUTHORIZATION_HEADER_NAME, authHeader);
    }
    
    private static Charset getCharset(HttpHeaders headers){
        Charset defaultCharset = Charset.defaultCharset();
        MediaType contentType = headers.getContentType();
        if(contentType != null){
            Charset charset = contentType.getCharset();
            if(charset != null){
                return charset;
            }
        }
        return defaultCharset;
    }
}
