package com.mastercard.developer.oauth;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;

public enum Util {
  INSTANCE;
  private static final char[] b64chars = {
      'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
      'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
      'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
      'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'};

  /**
   * Percent encodes entities as per https://tools.ietf.org/html/rfc3986
   *
   * @param str - string to encode
   * @param charset - desired charset encoding
   * @return The percent encoded string in specified charset encoding
   */
  public static String percentEncode(String str, Charset charset) {
    if (str == null || str.isEmpty()) {
      return OAuth.EMPTY_STRING;
    }

    try {
      return URLEncoder.encode(str, charset.name())
          .replace("+", "%20")
          .replace("*", "%2A")
          .replace("%7E", "~");
    } catch (UnsupportedEncodingException e) {
      throw new IllegalArgumentException("Unable to decode URL using " + charset.displayName() + " encoding", e);
    }
  }

  // Base 64 encoder to maintain compatibility with Java 1.6
  public static String b64Encode(final byte[] data) {
    StringBuilder buffer = new StringBuilder();
    int pad = 0;
    for (int i = 0; i < data.length; i += 3) {

      int b = ((data[i] & 0xFF) << 16) & 0xFFFFFF;
      if (i + 1 < data.length) {
        b |= (data[i + 1] & 0xFF) << 8;
      } else {
        pad++;
      }
      if (i + 2 < data.length) {
        b |= (data[i + 2] & 0xFF);
      } else {
        pad++;
      }

      for (int j = 0; j < 4 - pad; j++) {
        int c = (b & 0xFC0000) >> 18;
        buffer.append(b64chars[c]);
        b <<= 6;
      }
    }
    for (int j = 0; j < pad; j++) {
      buffer.append("=");
    }

    return buffer.toString();
  }
}