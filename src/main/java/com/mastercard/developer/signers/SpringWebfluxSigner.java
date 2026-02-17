package com.mastercard.developer.signers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mastercard.developer.oauth.OAuth;
import com.mastercard.developer.oauth.SignatureMethod;
import org.springframework.http.ReactiveHttpOutputMessage;
import org.springframework.web.reactive.function.BodyInserter;
import org.springframework.web.reactive.function.BodyInserters;
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

    public SpringWebfluxSigner(String consumerKey, PrivateKey signingKey, SignatureMethod signatureMethod) {
        super(consumerKey, signingKey, signatureMethod);
    }

    public ClientRequest sign(ClientRequest request) throws Exception {
        URI uri = request.url();
        String method = request.method().name();
        BodyInserterWrapper<Object> bodyInserterWrapper = (BodyInserterWrapper<Object>) request.body();
        String payload = new ObjectMapper().writeValueAsString(bodyInserterWrapper.getBody());

        String authHeader = OAuth.getAuthorizationHeader(uri, method, payload, charset, consumerKey, signingKey, signatureMethod);

        // Add auth header
        return Mono.just(ClientRequest.from(request)
                .headers(headers -> headers.add(OAuth.AUTHORIZATION_HEADER_NAME, authHeader))
                .build()).block();
    }
}

class BodyInserterWrapper<T> implements BodyInserter<T, ReactiveHttpOutputMessage> {
    private final T body;
    private final BodyInserter<T, ReactiveHttpOutputMessage> delegate;

    public BodyInserterWrapper(T body) {
        this.body = body;
        this.delegate = BodyInserters.fromValue(body);
    }

    @Override
    public Mono<Void> insert(
            ReactiveHttpOutputMessage outputMessage,
            BodyInserter.Context context
    ) {
        return delegate.insert(outputMessage, context);
    }

    public T getBody() {
        return body;
    }
}
