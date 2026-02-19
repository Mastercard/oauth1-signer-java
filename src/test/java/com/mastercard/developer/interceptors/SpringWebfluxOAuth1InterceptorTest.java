package com.mastercard.developer.interceptors;

import com.mastercard.developer.oauth.OAuth;
import com.mastercard.developer.oauth.SignatureMethod;
import com.mastercard.developer.signers.SpringWebfluxSigner;
import com.mastercard.developer.test.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.security.PrivateKey;

class SpringWebfluxOAuth1InterceptorTest {

    @Test
    void constructor_shouldInstantiateSignerWithDefaultSignatureMethod() throws Exception {
        PrivateKey signingKey = TestUtils.getTestSigningKey();
        String consumerKey = "consumer-key";
        MockedConstruction.Context[] capturedContext = new MockedConstruction.Context[1];

        try (MockedConstruction<SpringWebfluxSigner> mocked = Mockito.mockConstruction(
                SpringWebfluxSigner.class,
                (mock, context) -> capturedContext[0] = context)) {
            new SpringWebfluxOAuth1Interceptor(consumerKey, signingKey);

            Assertions.assertEquals(1, mocked.constructed().size());
            MockedConstruction.Context context = capturedContext[0];
            Assertions.assertEquals(consumerKey, context.arguments().get(0));
            Assertions.assertEquals(signingKey, context.arguments().get(1));
            Assertions.assertEquals(OAuth.DEFAULT_SIGNATURE_METHOD, context.arguments().get(2));
        }
    }

    @ParameterizedTest
    @EnumSource(SignatureMethod.class)
    void constructor_shouldInstantiateSignerWithGivenSignatureMethod(SignatureMethod signatureMethod) throws Exception {
        PrivateKey signingKey = TestUtils.getTestSigningKey();
        String consumerKey = "consumer-key";
        MockedConstruction.Context[] capturedContext = new MockedConstruction.Context[1];

        try (MockedConstruction<SpringWebfluxSigner> mocked = Mockito.mockConstruction(
                SpringWebfluxSigner.class,
                (mock, context) -> capturedContext[0] = context)) {
            new SpringWebfluxOAuth1Interceptor(consumerKey, signingKey, signatureMethod);

            Assertions.assertEquals(1, mocked.constructed().size());
            MockedConstruction.Context context = capturedContext[0];
            Assertions.assertEquals(consumerKey, context.arguments().get(0));
            Assertions.assertEquals(signingKey, context.arguments().get(1));
            Assertions.assertEquals(signatureMethod, context.arguments().get(2));
        }
    }

    @Test
    void filter_shouldSignRequestAndProceed() throws Exception {
        ClientRequest request = ClientRequest.create(HttpMethod.GET, URI.create("https://api.mastercard.com/resource")).build();
        ClientRequest signedRequest = ClientRequest.create(HttpMethod.GET, URI.create("https://api.mastercard.com/resource")).build();
        ExchangeFunction next = Mockito.mock(ExchangeFunction.class);
        ClientResponse expectedResponse = Mockito.mock(ClientResponse.class);
        PrivateKey signingKey = TestUtils.getTestSigningKey();
        String consumerKey = "consumer-key";

        Mockito.when(next.exchange(Mockito.any(ClientRequest.class))).thenReturn(Mono.just(expectedResponse));

        try (MockedConstruction<SpringWebfluxSigner> mocked = Mockito.mockConstruction(SpringWebfluxSigner.class)) {
            SpringWebfluxOAuth1Interceptor instanceUnderTest = new SpringWebfluxOAuth1Interceptor(consumerKey, signingKey, SignatureMethod.RSA_SHA256);
            SpringWebfluxSigner signerMock = mocked.constructed().get(0);
            Mockito.when(signerMock.sign(request)).thenReturn(signedRequest);

            ClientResponse actualResponse = instanceUnderTest.filter(request, next).block();

            Mockito.verify(signerMock).sign(request);
            Mockito.verify(next).exchange(signedRequest);
            Assertions.assertSame(expectedResponse, actualResponse);
        }
    }
}
