# oauth1-signer-java

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://developer.mastercard.com/_/_/src/global/assets/svg/mcdev-logo-light.svg">
  <img src="https://developer.mastercard.com/_/_/src/global/assets/svg/mcdev-logo-dark.svg" alt="mastercard developers logo">
</picture>

[![](https://github.com/Mastercard/oauth1-signer-java/workflows/Build%20&%20Test/badge.svg)](https://github.com/Mastercard/oauth1-signer-java/actions?query=workflow%3A%22Build+%26+Test%22)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_oauth1-signer-java&metric=alert_status)](https://sonarcloud.io/dashboard?id=Mastercard_oauth1-signer-java)
[![](https://github.com/Mastercard/oauth1-signer-java/workflows/broken%20links%3F/badge.svg)](https://github.com/Mastercard/oauth1-signer-java/actions?query=workflow%3A%22broken+links%3F%22)
[![](https://img.shields.io/maven-central/v/com.mastercard.developer/oauth1-signer.svg)](https://central.sonatype.com/artifact/com.mastercard.developer/oauth1-signer?smo=true)
[![](https://www.javadoc.io/badge/com.mastercard.developer/oauth1-signer.svg?color=blue)](https://www.javadoc.io/doc/com.mastercard.developer/oauth1-signer)
[![](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/Mastercard/oauth1-signer-java/blob/master/LICENSE)

## Table of Contents
- [Overview](#overview)
  * [Compatibility](#compatibility)
  * [References](#references)
  * [Versioning and Deprecation Policy](#versioning)
- [Usage](#usage)
  * [Prerequisites](#prerequisites)
  * [Adding the Library to Your Project](#adding-the-library-to-your-project)
  * [Loading the Signing Key](#loading-the-signing-key) 
  * [Creating the OAuth Authorization Header](#creating-the-oauth-authorization-header)
  * [Signing HTTP Client Request Objects](#signing-http-client-request-objects)
  * [Integrating with OpenAPI Generator API Client Libraries](#integrating-with-openapi-generator-api-client-libraries)

## Overview <a name="overview"></a>
Zero dependency library for generating a Mastercard API compliant OAuth signature.

### Compatibility <a name="compatibility"></a>
Java 11+ till version 1.5.3 included.
Java 17+ from 1.5.4

### References <a name="references"></a>
* [OAuth 1.0a specification](https://tools.ietf.org/html/rfc5849)
* [Body hash extension for non application/x-www-form-urlencoded payloads](https://tools.ietf.org/id/draft-eaton-oauth-bodyhash-00.html)

### Versioning and Deprecation Policy <a name="versioning"></a>
* [Mastercard Versioning and Deprecation Policy](https://github.com/Mastercard/.github/blob/main/CLIENT_LIBRARY_DEPRECATION_POLICY.md)

## Usage <a name="usage"></a>
### Prerequisites <a name="prerequisites"></a>
Before using this library, you will need to set up a project in the [Mastercard Developers Portal](https://developer.mastercard.com). 

As part of this set up, you'll receive credentials for your app:
* A consumer key (displayed on the Mastercard Developer Portal)
* A private request signing key (matching the public certificate displayed on the Mastercard Developer Portal)

### Adding the Library to Your Project <a name="adding-the-library-to-your-project"></a>

#### Maven
```xml
<dependency>
    <groupId>com.mastercard.developer</groupId>
    <artifactId>oauth1-signer</artifactId>
    <version>${oauth1-signer-version}</version>
</dependency>
```

#### Gradle
```
dependencies {
    implementation "com.mastercard.developer:oauth1-signer:$oauth1SignerVersion"
}
```

#### Other Dependency Managers
See: https://central.sonatype.com/artifact/com.mastercard.developer/oauth1-signer?smo=true

### Loading the Signing Key <a name="loading-the-signing-key"></a>

A `PrivateKey` key object can be created by calling the `AuthenticationUtils.loadSigningKey` method:
```java
PrivateKey signingKey = AuthenticationUtils.loadSigningKey(
                                    "<insert PKCS#12 key file path>", 
                                    "<insert key alias>", 
                                    "<insert key password>");
```

### Creating the OAuth Authorization Header <a name="creating-the-oauth-authorization-header"></a>
The method that does all the heavy lifting is `OAuth.getAuthorizationHeader`. You can call into it directly and as long as you provide the correct parameters, it will return a string that you can add into your request's `Authorization` header.

```java
String consumerKey = "<insert consumer key>";
URI uri = URI.create("https://sandbox.api.mastercard.com/service");
String method = "POST";
String payload = "Hello world!";
Charset charset = StandardCharsets.UTF_8;
String authHeader = OAuth.getAuthorizationHeader(uri, method, payload, charset, consumerKey, signingKey);
```

#### RSA-PSS support

This library signs requests using OAuth 1.0a with an RSA + SHA-256 digest.

* When the runtime/provider supports the JCA algorithm `SHA256withRSA`, the library uses it (RSA PKCS#1 v1.5).
  In this case, the Authorization header contains `oauth_signature_method="RSA-SHA256"`.
* If `SHA256withRSA` is not usable and RSA-PSS is, the library falls back to the JCA algorithm `RSASSA-PSS` using
  `SHA-256 / MGF1(SHA-256) / saltLen=32 / trailerField=1`.
  In this case, the Authorization header contains `oauth_signature_method="RSA-PSS"`.

Notes:
* The RSA signature scheme (PKCS#1 v1.5 vs PSS) cannot be inferred from an RSA `PrivateKey`.
  The selection is based on provider capabilities.
* If you want to know which JCA algorithm will be used on the current runtime/provider, you can call:

```java
String alg = OAuth.signSignatureBaseStringAlgName("baseString", signingKey, StandardCharsets.UTF_8);
System.out.println(alg); // "SHA256withRSA" or "RSASSA-PSS"
```

### Signing HTTP Client Request Objects <a name="signing-http-client-request-objects"></a>

Alternatively, you can use helper classes for some of the commonly used HTTP clients.

These classes, provided in the `com.mastercard.developer.signers` package, will modify the provided request object in-place and will add the correct `Authorization` header. Once instantiated with a consumer key and private key, these objects can be reused. 

Usage briefly described below, but you can also refer to the test package for examples. 

+ [Java HttpsURLConnection](#java-httpsurlconnection)
+ [Apache HTTP Client 4](#apache-http-client-4)
+ [OkHttp 3](#okhttp-3)
+ [Spring Webflux](#spring-webflux)

#### Java HttpsURLConnection <a name="java-httpsurlconnection"></a>
```java
Charset charset = StandardCharsets.UTF_8;
URL url = new URL("https://sandbox.api.mastercard.com/service");
String payload = "{\"foo\":\"bar\"}";

HttpsURLConnection con = (HttpsURLConnection)url.openConnection();
con.setRequestMethod("POST");
con.setRequestProperty("Content-Type", "application/json; charset=" + charset.name());

HttpsUrlConnectionSigner signer = new HttpsUrlConnectionSigner(charset, consumerKey, signingKey);
signer.sign(con, payload);
```

#### Apache HTTP Client 4 <a name="apache-http-client-4"></a>
```java
String payload = "{\"foo\":\"bar\"}";

HttpClient httpClient = HttpClientBuilder.create().build();
HttpPost httpPost = new HttpPost("https://sandbox.api.mastercard.com/service");
httpPost.setEntity(new StringEntity(payload, ContentType.APPLICATION_JSON));

ApacheHttpClient4Signer signer = new ApacheHttpClient4Signer(consumerKey, signingKey);
signer.sign(httpPost);
```

#### OkHttp 3 <a name="okhttp-3"></a>
```java
MediaType JSON = MediaType.parse("application/json; charset=utf-8");
String payload = "{\"foo\":\"bar\"}";

OkHttpClient client = new OkHttpClient();
RequestBody body = RequestBody.create(JSON, payload);
Request.Builder request = new Request.Builder()
        .url("https://sandbox.api.mastercard.com/service")
        .post(body);

OkHttpSigner signer = new OkHttpSigner(consumerKey, signingKey);
signer.sign(request);
```

#### Spring Webflux <a name="spring-webflux"></a>
```java
WebClient client = WebClient.create();
ClientRequest request = ClientRequest.create(HttpMethod.POST, URI.create("https://api.mastercard.com/service"))
        .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
        .body(BodyInserters.fromValue(new BodyInserterWrapper(yourRequestObject)))
        .build();

SpringWebfluxSigner signer = new SpringWebfluxSigner(consumerKey, signingKey);
ClientRequest signedRequest = signer.sign(request);
client.exchange(signedRequest);
```

### Integrating with OpenAPI Generator API Client Libraries <a name="integrating-with-openapi-generator-api-client-libraries"></a>

[OpenAPI Generator](https://github.com/OpenAPITools/openapi-generator) generates API client libraries from [OpenAPI Specs](https://github.com/OAI/OpenAPI-Specification). 
It provides generators and library templates for supporting multiple languages and frameworks.

The `com.mastercard.developer.interceptors` package will provide you with some request interceptor classes you can use when configuring your API client. These classes will take care of adding the correct `Authorization` header before sending the request.

Library options currently supported for the `java` generator:
+ [okhttp-gson](#okhttp-gson)
+ [feign](#feign)
+ [retrofit](#retrofit)
+ [retrofit2](#retrofit2)
+ [google-api-client](#google-api-client)
+ [spring-webflux](#spring-webflux-interceptor)

See also:
* [OpenAPI Generator (maven Plugin)](https://mvnrepository.com/artifact/org.openapitools/openapi-generator-maven-plugin)
* [OpenAPI Generator (executable)](https://mvnrepository.com/artifact/org.openapitools/openapi-generator-cli)
* [CONFIG OPTIONS for java](https://github.com/OpenAPITools/openapi-generator/blob/master/docs/generators/java.md)

#### okhttp-gson <a name="okhttp-gson"></a>
##### OpenAPI Generator Plugin Configuration
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>okhttp-gson</library>
    <!-- ... -->
</configuration>
```

##### Usage of the `OkHttp2OAuth1Interceptor` (OpenAPI Generator 3.3.x)
```java
ApiClient client = new ApiClient();
client.setBasePath("https://sandbox.api.mastercard.com");
List<Interceptor> interceptors = client.getHttpClient().interceptors();
interceptors.add(new OkHttp2OAuth1Interceptor(consumerKey, signingKey));
ServiceApi serviceApi = new ServiceApi(client);
// ...
```

##### Usage of the `OkHttpOAuth1Interceptor` (OpenAPI Generator 4+)
```java
ApiClient client = new ApiClient();
client.setBasePath("https://sandbox.api.mastercard.com");
Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("https://proxy-url.com", 8866)); // Optional Proxy Configuration
client.setHttpClient(
    client.getHttpClient()
        .newBuilder()
        .proxy(proxy) // Optional proxy
        .addInterceptor(new OkHttpOAuth1Interceptor(consumerKey, signingKey))
        .build()
);
ServiceApi serviceApi = new ServiceApi(client);
// ...
```

#### feign <a name="feign"></a>
##### OpenAPI Generator Plugin Configuration
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>feign</library>
    <!-- ... -->
</configuration>
```

##### Usage of the `OpenFeignOAuth1Interceptor`
```java
ApiClient client = new ApiClient();
client.setBasePath("https://sandbox.api.mastercard.com");
Feign.Builder feignBuilder = client.getFeignBuilder();
ArrayList<RequestInterceptor> interceptors = new ArrayList<>();
interceptors.add(new OpenFeignOAuth1Interceptor(consumerKey, signingKey, client.getBasePath()));
feignBuilder.requestInterceptors(interceptors);
ServiceApi serviceApi = client.buildClient(ServiceApi.class);
// ...
```

#### retrofit <a name="retrofit"></a>
##### OpenAPI Generator Plugin Configuration
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>retrofit</library>
    <!-- ... -->
</configuration>
```

##### Usage of the `OkHttp2OAuth1Interceptor`
```java
ApiClient client = new ApiClient();
RestAdapter.Builder adapterBuilder = client.getAdapterBuilder();
adapterBuilder.setEndpoint("https://sandbox.api.mastercard.com"); 
List<Interceptor> interceptors = client.getOkClient().interceptors();
interceptors.add(new OkHttp2OAuth1Interceptor(consumerKey, signingKey));
ServiceApi serviceApi = client.createService(ServiceApi.class);
// ...
```

#### retrofit2 <a name="retrofit2"></a>
##### OpenAPI Generator Plugin Configuration
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>retrofit2</library>
    <!-- ... -->
</configuration>
```

##### Usage of the `OkHttpOAuth1Interceptor`
```java
ApiClient client = new ApiClient();
Retrofit.Builder adapterBuilder = client.getAdapterBuilder();
adapterBuilder.baseUrl("https://sandbox.api.mastercard.com"); 
OkHttpClient.Builder okBuilder = client.getOkBuilder();
okBuilder.addInterceptor(new OkHttpOAuth1Interceptor(consumerKey, signingKey));
ServiceApi serviceApi = client.createService(ServiceApi.class);
// ...
```

#### google-api-client <a name="google-api-client"></a>
##### OpenAPI Generator Plugin Configuration
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>google-api-client</library>
    <!-- ... -->
</configuration>
```

##### Usage of the `HttpExecuteOAuth1Interceptor`
```java
HttpRequestInitializer initializer = new HttpRequestInitializer() {
    @Override
    public void initialize(HttpRequest request) {
        request.setInterceptor(new HttpExecuteOAuth1Interceptor(consumerKey, signingKey));
    }
};
ApiClient client = new ApiClient("https://sandbox.api.mastercard.com", null, initializer, null);
ServiceApi serviceApi = client.serviceApi();
// ...
```

#### spring-webflux <a name="spring-webflux-interceptor"></a>
##### OpenAPI Generator Plugin Configuration
```xml
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>spring</generatorName>
    <library>spring-cloud</library>
    <!-- ... -->
</configuration>
```

##### Usage of the `HttpExecuteOAuth1Interceptor`
```java
WebClient.Builder webClientBuilder = WebClient.builder()
  .baseUrl("https://api.mastercard.com/service")
  .filter(new SpringWebfluxOAuth1Interceptor(consumerKey, signingKey));

ApiClient apiClient = new ApiClient(webClientBuilder);
ServiceApi serviceApi = client.serviceApi();
// ...
```
