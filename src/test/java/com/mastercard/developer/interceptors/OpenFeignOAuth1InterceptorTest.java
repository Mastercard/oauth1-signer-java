package com.mastercard.developer.interceptors;

import com.mastercard.developer.oauth.SignatureMethod;
import com.mastercard.developer.signers.OpenFeignSigner;
import com.mastercard.developer.test.TestUtils;
import feign.RequestTemplate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;

import java.security.PrivateKey;

class OpenFeignOAuth1InterceptorTest {

    @ParameterizedTest
    @EnumSource(SignatureMethod.class)
    void constructor_shouldInstantiateSignerWithGivenSignatureMethod(SignatureMethod signatureMethod) throws Exception {
        PrivateKey signingKey = TestUtils.getTestSigningKey();
        String consumerKey = "consumer-key";
        String baseUri = "https://api.mastercard.com";
        MockedConstruction.Context[] capturedContext = new MockedConstruction.Context[1];

        try (MockedConstruction<OpenFeignSigner> mocked = Mockito.mockConstruction(
                OpenFeignSigner.class,
                (mock, context) -> capturedContext[0] = context)) {
            new OpenFeignOAuth1Interceptor(consumerKey, signingKey, baseUri, signatureMethod);

            Assertions.assertEquals(1, mocked.constructed().size());
            MockedConstruction.Context context = capturedContext[0];
            Assertions.assertEquals(consumerKey, context.arguments().get(0));
            Assertions.assertEquals(signingKey, context.arguments().get(1));
            Assertions.assertEquals(baseUri, context.arguments().get(2));
            Assertions.assertEquals(signatureMethod, context.arguments().get(3));
        }
    }

    @Test
    void apply_shouldSignRequest() throws Exception {
        RequestTemplate requestTemplate = Mockito.mock(RequestTemplate.class);
        PrivateKey signingKey = TestUtils.getTestSigningKey();
        String consumerKey = "consumer-key";
        String baseUri = "https://api.mastercard.com";

        try (MockedConstruction<OpenFeignSigner> mocked = Mockito.mockConstruction(OpenFeignSigner.class)) {
            OpenFeignOAuth1Interceptor instanceUnderTest = new OpenFeignOAuth1Interceptor(consumerKey, signingKey, baseUri, SignatureMethod.RSA_SHA256);
            OpenFeignSigner signerMock = mocked.constructed().get(0);

            instanceUnderTest.apply(requestTemplate);

            Mockito.verify(signerMock).sign(requestTemplate);
        }
    }
}
