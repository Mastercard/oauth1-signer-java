package com.mastercard.developer.interceptors;

import com.google.api.client.http.HttpRequest;
import com.mastercard.developer.oauth.SignatureMethod;
import com.mastercard.developer.signers.GoogleApiClientSigner;
import com.mastercard.developer.test.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;

import java.security.PrivateKey;

class HttpExecuteOAuth1InterceptorTest {

    @ParameterizedTest
    @EnumSource(SignatureMethod.class)
    void constructor_shouldInstantiateSignerWithGivenSignatureMethod(SignatureMethod signatureMethod) throws Exception {
        PrivateKey signingKey = TestUtils.getTestSigningKey();
        String consumerKey = "consumer-key";
        MockedConstruction.Context[] capturedContext = new MockedConstruction.Context[1];

        try (MockedConstruction<GoogleApiClientSigner> mocked = Mockito.mockConstruction(
                GoogleApiClientSigner.class,
                (mock, context) -> capturedContext[0] = context)) {
            new HttpExecuteOAuth1Interceptor(consumerKey, signingKey, signatureMethod);

            Assertions.assertEquals(1, mocked.constructed().size());
            MockedConstruction.Context context = capturedContext[0];
            Assertions.assertEquals(consumerKey, context.arguments().get(0));
            Assertions.assertEquals(signingKey, context.arguments().get(1));
            Assertions.assertEquals(signatureMethod, context.arguments().get(2));
        }
    }

    @Test
    void intercept_shouldSignRequest() throws Exception {
        HttpRequest request = Mockito.mock(HttpRequest.class);
        PrivateKey signingKey = TestUtils.getTestSigningKey();
        String consumerKey = "consumer-key";

        try (MockedConstruction<GoogleApiClientSigner> mocked = Mockito.mockConstruction(GoogleApiClientSigner.class)) {
            HttpExecuteOAuth1Interceptor instanceUnderTest = new HttpExecuteOAuth1Interceptor(consumerKey, signingKey, SignatureMethod.RSA_SHA256);
            GoogleApiClientSigner signerMock = mocked.constructed().get(0);

            instanceUnderTest.intercept(request);

            Mockito.verify(signerMock).sign(request);
        }
    }
}