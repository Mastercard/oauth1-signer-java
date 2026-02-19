package com.mastercard.developer.interceptors;

import com.mastercard.developer.signers.SpringWebfluxSigner;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import reactor.core.publisher.Mono;

import java.security.PrivateKey;

/**
 * A Spring webflux request interceptor for handling OAuth1.0a
 */
public class SpringWebfluxOAuth1Interceptor implements ExchangeFilterFunction {

    private final SpringWebfluxSigner signer;

    public SpringWebfluxOAuth1Interceptor(String consumerKey, PrivateKey signingKey) {
        this.signer = new SpringWebfluxSigner(consumerKey, signingKey);
    }

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        try {
            ClientRequest req = signer.sign(request);
            return next.exchange(req).doOnNext(response -> {});
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}