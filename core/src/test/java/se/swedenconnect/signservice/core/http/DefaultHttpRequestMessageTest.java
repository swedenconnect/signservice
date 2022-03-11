/*
 * MIT License
 *
 * Copyright 2022 Sweden Connect
 */
package se.swedenconnect.signservice.core.http;

import java.net.MalformedURLException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

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

  @Test
  public void testBasicGetMethod() throws Exception {
    final DefaultHttpRequestMessage message = new DefaultHttpRequestMessage("GET", BASE_URL);
    message.addHttpParameter("Param1", PARAM1);
    message.addHttpParameter("Param2", PARAM2);
    message.addHttpHeader(HEADER, HEADER_VALUE);

    Assertions.assertEquals(BASE_URL + "?Param1=" + ENCODED_PARAM1 + "&Param2=" + ENCODED_PARAM2,
        message.getUrl());

    Assertions.assertTrue(message.getHttpHeaders().size() == 1);
    Assertions.assertTrue(message.getHttpParameters().size() == 2);
  }

  @Test
  public void testGetMethodParamSuppliedInConstructor() throws Exception {
    final DefaultHttpRequestMessage message = new DefaultHttpRequestMessage("GET", BASE_URL + "?Param1=" + ENCODED_PARAM1);
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
  public void testBadUrl() throws Exception {
    final IllegalArgumentException ex = Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new DefaultHttpRequestMessage("GET", "xyz://not-a-valid.url");
    });

    Assertions.assertTrue(MalformedURLException.class.isInstance(ex.getCause()));
  }

}
