# Table of contents
- [Overview](#overview)
  * [Compatibility](#compatibility)
  * [References](#references)
- [Usage](#usage)
  * [Maven](#maven)
  * [Prerequisites](#prerequisites)
  * [Creating a valid OAuth string](#creating-a-valid-oauth-string)
  * [Using HTTP client helpers](#using-http-client-helpers)
    + [Java HttpsURLConnection](#java-httpsurlconnection)
    + [Apache HTTP Client 4](#apache-http-client-4)
    + [OKHttp](#okhttp)

# Overview
Zero dependency library for generating a Mastercard API compliant OAuth signature.

## Compatibility
Java 1.6+

## References
[OAuth 1.0a specification](https://tools.ietf.org/html/rfc5849)

[Body hash extension for non application/x-www-form-urlencoded payloads](https://tools.ietf.org/id/draft-eaton-oauth-bodyhash-00.html)

# Usage
## Maven

```
<dependency>
    <groupId>com.mastercard.developer</groupId>
    <artifactId>oauth1-signer</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Prerequisites
Before using this library, you will need to set up a project and key in the [Mastercard Developers Portal](https://developer.mastercard.com). 

The two key pieces of information you will need are:

* Consumer key
* Private key matching the public key uploaded to Mastercard Developer Portal

## Creating a valid OAuth string
The method that does all the heavy lifting is `OAuth.getAuthorizationHeader`. You can call into it directly and as long as you provide the correct parameters, it will return a string that you can add into your request's `Authorization` header. 

```java
String consumerKey = <insert consumer key from developer portal>;
PrivateKey signingKey = <initialize private key matching the consumer key>;
URI uri = URI.create("https://sandbox.api.mastercard.com/service");
String method = "GET";
String payload = "Hello world!";
Charset charset = Charset.forName("UTF-8");

String authHeader = OAuth.getAuthorizationHeader(uri, method, payload, charset, consumerKey, signingKey);
```

## Using HTTP client helpers
Alternatively, you can use a helper class for some of the commonly used HTTP clients provided in the `com.mastercard.developer.signers` package. These classes will modify the provided request object in-place and add the correct Authorization header. Once instantiated with a consumer key and private key, these objects can be reused. Usage briefly described below, but you can also refer to the test package for examples. 

### Java HttpsURLConnection
```java
String consumerKey = <insert consumer key from developer portal>;
PrivateKey signingKey = <initialize private key matching the consumer key>;
Charset charset = Charset.forName("UTF-8");
URL url = new URL("https://sandbox.api.mastercard.com/service");
String payload = "{\"foo\":\"bar\"}";

HttpsURLConnection con = (HttpsURLConnection)url.openConnection();
con.setRequestMethod("POST");
con.setRequestProperty("Content-Type", "application/json; charset=" + charset.name());

HttpsUrlConnectionSigner signer = new HttpsUrlConnectionSigner(charset, consumerKey, signingKey);
signer.sign(con, payload);
```

### Apache HTTP Client 4
```java
String consumerKey = <insert consumer key from developer portal>;
PrivateKey signingKey = <initialize private key matching the consumer key>;
String payload = "{\"foo\":\"bar\"}";

HttpClient httpClient = HttpClientBuilder.create().build();
HttpPost httpPost = new HttpPost("https://sandbox.api.mastercard.com/service");
httpPost.setEntity(new StringEntity(payload, ContentType.APPLICATION_JSON));

ApacheHttpClient4Signer signer = new ApacheHttpClient4Signer(consumerKey, signingKey);
signer.sign(httpPost);
```

### OkHttp 3.x
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
