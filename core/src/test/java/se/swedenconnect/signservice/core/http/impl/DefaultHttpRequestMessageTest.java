/*
 * Copyright 2022 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.signservice.core.http.impl;

import java.net.MalformedURLException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.core.http.HttpRequestMessage;

/**
 * Test cases for DefaultHttpRequestMessage.
 */
public class DefaultHttpRequestMessageTest {

  private static String BASE_URL = "https://www.example.com/response";
  private static String PARAM1 = "ABCDEF 12345/98";
  private static String ENCODED_PARAM1 = URLEncoder.encode(PARAM1, StandardCharsets.UTF_8);
  private static String PARAM2 = "BAHM=";
  private static String ENCODED_PARAM2 = URLEncoder.encode(PARAM2, StandardCharsets.UTF_8);
  private static String HEADER = "Cache-control";
  private static String HEADER_VALUE = "no-cache, no-store";
  private static String HEADER2 = "User-Agent";
  private static String HEADER_VALUE2 = "Mozilla/5.0 Firefox/26.0";

  @Test
  public void testBasicGetMethod() throws Exception {
    final DefaultHttpRequestMessage message = new DefaultHttpRequestMessage("GET", BASE_URL);
    message.addHttpParameter("Param1", PARAM1);
    message.addHttpParameter("Param2", PARAM2);
    message.addHttpHeader(HEADER, HEADER_VALUE);
    message.addHttpHeader(HEADER2, HEADER_VALUE2);

    Assertions.assertEquals(HttpRequestMessage.GET_METHOD, message.getMethod());
    Assertions.assertEquals(BASE_URL + "?Param1=" + ENCODED_PARAM1 + "&Param2=" + ENCODED_PARAM2,
        message.getUrl());

    Assertions.assertTrue(message.getHttpHeaders().size() == 2);
    Assertions.assertTrue(message.getHttpParameters().size() == 2);
  }

  @Test
  public void testGetMethodParamSuppliedInConstructor() throws Exception {
    final DefaultHttpRequestMessage message = new DefaultHttpRequestMessage("GET",
        BASE_URL + "?Param1=" + ENCODED_PARAM1);
    message.addHttpParameter("Param2", PARAM2);
    message.addHttpHeader(HEADER, HEADER_VALUE);

    Assertions.assertEquals(BASE_URL + "?Param1=" + ENCODED_PARAM1 + "&Param2=" + ENCODED_PARAM2,
        message.getUrl());

    Assertions.assertTrue(message.getHttpHeaders().size() == 1);
    Assertions.assertTrue(message.getHttpParameters().size() == 2);
  }

  @Test
  public void testGetMethodOrdering() throws Exception {
    final DefaultHttpRequestMessage message = new DefaultHttpRequestMessage("GET", BASE_URL);
    message.addHttpParameter("Param2", PARAM2);
    message.addHttpParameter("Param1", PARAM1);
    message.addHttpHeader(HEADER, HEADER_VALUE);

    Assertions.assertEquals(BASE_URL + "?Param2=" + ENCODED_PARAM2 + "&Param1=" + ENCODED_PARAM1,
        message.getUrl());

    Assertions.assertTrue(message.getHttpHeaders().size() == 1);
    Assertions.assertTrue(message.getHttpParameters().size() == 2);
  }

  @Test
  public void testNoParams() {
    final DefaultHttpRequestMessage message = new DefaultHttpRequestMessage("GET", BASE_URL);
    Assertions.assertEquals(BASE_URL, message.getUrl());
    Assertions.assertTrue(message.getHttpParameters().isEmpty());
    Assertions.assertTrue(message.getHttpHeaders().isEmpty());
  }

  @Test
  public void testBasicPostMethod() throws Exception {
    final DefaultHttpRequestMessage message = new DefaultHttpRequestMessage("POST", BASE_URL);
    message.addHttpParameter("Param1", PARAM1);
    message.addHttpParameter("Param2", PARAM2);
    message.addHttpHeader(HEADER, HEADER_VALUE);

    Assertions.assertEquals(BASE_URL, message.getUrl());

    Assertions.assertTrue(message.getHttpHeaders().size() == 1);
    Assertions.assertTrue(message.getHttpParameters().size() == 2);
  }

  @Test
  public void testPostMethodWithQueryParam() throws Exception {
    final DefaultHttpRequestMessage message = new DefaultHttpRequestMessage("POST", BASE_URL + "?hello=1");
    message.addHttpParameter("Param1", PARAM1);
    message.addHttpParameter("Param2", PARAM2);
    message.addHttpHeader(HEADER, HEADER_VALUE);

    Assertions.assertEquals(BASE_URL + "?hello=1", message.getUrl());

    Assertions.assertTrue(message.getHttpHeaders().size() == 1);
    Assertions.assertTrue(message.getHttpParameters().size() == 2);
  }

  @Test
  public void testUnsupportedMethod() throws Exception {

    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new DefaultHttpRequestMessage("DELETE", BASE_URL);
    });

  }

  @Test
  public void missingMethod() {
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new DefaultHttpRequestMessage("", BASE_URL);
    }, "method must be set");
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new DefaultHttpRequestMessage(null, BASE_URL);
    }, "method must be set");
  }

  @Test
  public void testBadUrl() throws Exception {
    final IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new DefaultHttpRequestMessage("GET", "xyz://not-a-valid.url");
    });

    Assertions.assertTrue(MalformedURLException.class.isInstance(ex.getCause()));
  }

}