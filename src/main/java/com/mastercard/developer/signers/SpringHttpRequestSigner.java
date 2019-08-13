package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;

import java.nio.charset.Charset;
import java.security.PrivateKey;

import org.springframework.http.HttpRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

/**
 * Utility class for signing Spring RestTemplate requests.
 */
public class SpringHttpRequestSigner extends AbstractSigner {
    
    public SpringHttpRequestSigner(String consumerKey, PrivateKey signingKey) {
        super(consumerKey, signingKey);
    }
    
    public void sign(HttpRequest request, byte[] bytes) {
        HttpHeaders headers = request.getHeaders();
        Charset charset = getCharset(headers);
        String payload = (null==bytes ? null : new String(bytes, charset));
        String authHeader = OAuth.getAuthorizationHeader(request.getURI(), request.getMethod().toString(), payload, charset, consumerKey, signingKey);
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
