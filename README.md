# Table of Contents
- [Overview](#overview)
  * [Compatibility](#compatibility)
  * [References](#references)
- [Usage](#usage)
  * [Prerequisites](#prerequisites)
  * [Maven](#maven)
  * [Creating the OAuth Authorization Header](#creating-the-oauth-authorization-header)
  * [Signing HTTP Client Request Objects](#signing-http-client-request-objects)
  * [Integrating with OpenAPI Generator API Client Libraries](#integrating-with-openapi-generator-api-client-libraries)
  

# Overview <a name="overview"></a>
Zero dependency library for generating a Mastercard API compliant OAuth signature.

## Compatibility <a name="compatibility"></a>
Java 1.6+

## References <a name="references"></a>
[OAuth 1.0a specification](https://tools.ietf.org/html/rfc5849)

[Body hash extension for non application/x-www-form-urlencoded payloads](https://tools.ietf.org/id/draft-eaton-oauth-bodyhash-00.html)

# Usage <a name="usage"></a>
## Prerequisites <a name="prerequisites"></a>
Before using this library, you will need to set up a project in the [Mastercard Developers Portal](https://developer.mastercard.com). 

As part of this set up, you'll receive credentials for your app:
* A consumer key (displayed on the Mastercard Developer Portal)
* A private request signing key (matching the public certificate displayed on the Mastercard Developer Portal)

```java
String consumerKey = "<insert consumer key>";
PrivateKey signingKey = SecurityUtils.loadPrivateKey(
						"<insert PKCS#12 key file path>", 
						"<insert key alias>", 
						"<insert key password>");
```

## Maven <a name="maven"></a>

```
<dependency>
    <groupId>com.mastercard.developer</groupId>
    <artifactId>oauth1-signer</artifactId>
    <version>1.1.0</version>
</dependency>
```

## Creating the OAuth Authorization Header <a name="creating-the-oauth-authorization-header"></a>
The method that does all the heavy lifting is `OAuth.getAuthorizationHeader`. You can call into it directly and as long as you provide the correct parameters, it will return a string that you can add into your request's `Authorization` header.

```java
String consumerKey = "<insert consumer key>";
PrivateKey signingKey = SecurityUtils.loadPrivateKey(
						"<insert PKCS#12 key file path>", 
						"<insert key alias>", 
						"<insert key password>");

URI uri = URI.create("https://sandbox.api.mastercard.com/service");
String method = "GET";
String payload = "Hello world!";
Charset charset = Charset.forName("UTF-8");

String authHeader = OAuth.getAuthorizationHeader(uri, method, payload, charset, consumerKey, signingKey);
```

## Signing HTTP Client Request Objects <a name="signing-http-client-request-objects"></a>

Alternatively, you can use helper classes for some of the commonly used HTTP clients.

These classes, provided in the `com.mastercard.developer.signers` package, will modify the provided request object in-place and will add the correct `Authorization` header.

Once instantiated with a consumer key and private key, these objects can be reused. Usage briefly described below, but you can also refer to the test package for examples. 

+ [Java HttpsURLConnection](#java-httpsurlconnection)
+ [Apache HTTP Client 4](#apache-http-client-4)
+ [OkHttp 3](#okhttp-3)

### Java HttpsURLConnection <a name="java-httpsurlconnection"></a>
```java
Charset charset = Charset.forName("UTF-8");
URL url = new URL("https://sandbox.api.mastercard.com/service");
String payload = "{\"foo\":\"bar\"}";

HttpsURLConnection con = (HttpsURLConnection)url.openConnection();
con.setRequestMethod("POST");
con.setRequestProperty("Content-Type", "application/json; charset=" + charset.name());

HttpsUrlConnectionSigner signer = new HttpsUrlConnectionSigner(charset, consumerKey, signingKey);
signer.sign(con, payload);
```

### Apache HTTP Client 4 <a name="apache-http-client-4"></a>
```java
String payload = "{\"foo\":\"bar\"}";

HttpClient httpClient = HttpClientBuilder.create().build();
HttpPost httpPost = new HttpPost("https://sandbox.api.mastercard.com/service");
httpPost.setEntity(new StringEntity(payload, ContentType.APPLICATION_JSON));

ApacheHttpClient4Signer signer = new ApacheHttpClient4Signer(consumerKey, signingKey);
signer.sign(httpPost);
```

### OkHttp 3 <a name="okhttp-3"></a>
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

## Integrating with OpenAPI Generator API Client Libraries <a name="integrating-with-openapi-generator-api-client-libraries"></a>

[OpenAPI Generator](https://github.com/OpenAPITools/openapi-generator) generates API client libraries from [OpenAPI Specs](https://github.com/OAI/OpenAPI-Specification). 
It provides generators and library templates for supporting multiple languages and frameworks.

The `com.mastercard.developer.interceptors` package will provide you with some request interceptor classes you can use when configuring your API client. These classes will take care of adding the correct `Authorization` header before sending the request.

+ [okhttp-gson](#okhttp-gson)
+ [feign](#feign)
+ [retrofit](#retrofit)
+ [retrofit2](#retrofit2)
+ [google-api-client](#google-api-client)

### okhttp-gson <a name="okhttp-gson"></a>
#### OpenAPI Generator Plugin Configuration
```
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>okhttp-gson</library>
    <!-- ... -->
</configuration>
```

#### Usage of The OkHttp2OAuth1Interceptor
```java
ApiClient client = new ApiClient();
client.setBasePath("https://sandbox.api.mastercard.com");
List<Interceptor> interceptors = client.getHttpClient().networkInterceptors();
interceptors.add(new OkHttp2OAuth1Interceptor(consumerKey, signingKey));
ServiceApi serviceApi = new ServiceApi(client);
// ...
```

### feign <a name="feign"></a>
#### OpenAPI Generator Plugin Configuration
```
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>feign</library>
    <!-- ... -->
</configuration>
```

#### Usage of The OpenFeignOAuth1Interceptor
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

### retrofit <a name="retrofit"></a>
#### OpenAPI Generator Plugin Configuration
```
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>retrofit</library>
    <!-- ... -->
</configuration>
```

#### Usage of The OkHttp2OAuth1Interceptor
```java
ApiClient client = new ApiClient();
RestAdapter.Builder adapterBuilder = client.getAdapterBuilder();
adapterBuilder.setEndpoint("https://sandbox.api.mastercard.com"); 
List<Interceptor> interceptors = client.getOkClient().networkInterceptors();
interceptors.add(new OkHttp2OAuth1Interceptor(consumerKey, signingKey));
ServiceApi serviceApi = client.createService(ServiceApi.class);
// ...
```

### retrofit2 <a name="retrofit2"></a>
#### OpenAPI Generator Plugin Configuration
```
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>retrofit2</library>
    <!-- ... -->
</configuration>
```

#### Usage of The OkHttpOAuth1Interceptor
```java
ApiClient client = new ApiClient();
Retrofit.Builder adapterBuilder = client.getAdapterBuilder();
adapterBuilder.baseUrl("https://sandbox.api.mastercard.com"); 
OkHttpClient.Builder okBuilder = client.getOkBuilder();
okBuilder.addNetworkInterceptor(new OkHttpOAuth1Interceptor(consumerKey, signingKey));
ServiceApi serviceApi = client.createService(ServiceApi.class);
// ...
```

### google-api-client <a name="google-api-client"></a>
#### OpenAPI Generator Plugin Configuration
```
<configuration>
    <inputSpec>${project.basedir}/src/main/resources/openapi-spec.yaml</inputSpec>
    <generatorName>java</generatorName>
    <library>google-api-client</library>
    <!-- ... -->
</configuration>
```

#### Usage of The OAuth1HttpExecuteInterceptor
```java
HttpRequestInitializer initializer = new HttpRequestInitializer() {
    @Override
    public void initialize(HttpRequest request) {
        request.setInterceptor(new OAuth1HttpExecuteInterceptor(consumerKey, signingKey));
    }
};
ApiClient client = new ApiClient("https://sandbox.api.mastercard.com", null, initializer, null);
ServiceApi serviceApi = client.ServiceApi();
// ...
```