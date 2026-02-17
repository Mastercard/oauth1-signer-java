package com.mastercard.developer.interceptors;

import com.mastercard.developer.oauth.SignatureMethod;
import com.mastercard.developer.signers.OkHttpSigner;
import com.mastercard.developer.test.TestUtils;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.MockedConstruction;
import org.mockito.Mockito;

import java.security.PrivateKey;

class OkHttpOAuth1InterceptorTest {

    @ParameterizedTest
    @EnumSource(SignatureMethod.class)
    void constructor_shouldInstantiateSignerWithGivenSignatureMethod(SignatureMethod signatureMethod) throws Exception {
        PrivateKey signingKey = TestUtils.getTestSigningKey();
        String consumerKey = "consumer-key";
        MockedConstruction.Context[] capturedContext = new MockedConstruction.Context[1];

        try (MockedConstruction<OkHttpSigner> mocked = Mockito.mockConstruction(
                OkHttpSigner.class,
                (mock, context) -> capturedContext[0] = context)) {
            new OkHttpOAuth1Interceptor(consumerKey, signingKey, signatureMethod);

            Assertions.assertEquals(1, mocked.constructed().size());
            MockedConstruction.Context context = capturedContext[0];
            Assertions.assertEquals(consumerKey, context.arguments().get(0));
            Assertions.assertEquals(signingKey, context.arguments().get(1));
            Assertions.assertEquals(signatureMethod, context.arguments().get(2));
        }
    }

    @Test
    void intercept_shouldSignRequestAndProceed() throws Exception {
        Request request = new Request.Builder().url("https://api.mastercard.com/resource").build();
        Interceptor.Chain chain = Mockito.mock(Interceptor.Chain.class);
        Response expectedResponse = Mockito.mock(Response.class);
        PrivateKey signingKey = TestUtils.getTestSigningKey();
        String consumerKey = "consumer-key";

        Mockito.when(chain.request()).thenReturn(request);
        Mockito.when(chain.proceed(Mockito.any(Request.class))).thenReturn(expectedResponse);

        try (MockedConstruction<OkHttpSigner> mocked = Mockito.mockConstruction(OkHttpSigner.class)) {
            OkHttpOAuth1Interceptor instanceUnderTest = new OkHttpOAuth1Interceptor(consumerKey, signingKey, SignatureMethod.RSA_SHA256);
            OkHttpSigner signerMock = mocked.constructed().get(0);

            Response actualResponse = instanceUnderTest.intercept(chain);

            Mockito.verify(signerMock).sign(Mockito.any(Request.Builder.class));
            Mockito.verify(chain).proceed(Mockito.any(Request.class));
            Assertions.assertSame(expectedResponse, actualResponse);
        }
    }
}
