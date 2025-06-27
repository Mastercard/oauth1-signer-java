package com.mastercard.developer.signers;

import com.mastercard.developer.oauth.OAuth;
import org.springframework.web.reactive.function.client.ClientRequest;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.security.PrivateKey;

/**
 * Utility class for signing Spring webflux requests
 */
public class SpringWebfluxSigner extends AbstractSigner {

    public SpringWebfluxSigner(String consumerKey, PrivateKey signingKey) {
        super(consumerKey, signingKey);
    }

    public ClientRequest sign(ClientRequest request) throws Exception {
        URI uri = request.url();
        String method = request.method().name();

        String authHeader = OAuth.getAuthorizationHeader(uri, method, request.body().toString(), charset, consumerKey, signingKey);

        // Add auth header
        return Mono.just(ClientRequest.from(request)
                .headers(headers -> headers.add(OAuth.AUTHORIZATION_HEADER_NAME, authHeader))
                .build()).block();
    }
}
