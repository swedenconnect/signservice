/*
 * MIT License
 *
 * Copyright 2022 Sweden Connect
 */
package se.swedenconnect.signservice.core.http;

import java.util.Map;

/**
 * An interface representing a HTTP request message.
 */
public interface HttpRequestMessage {

  /** Symbolic constant for the GET method. */
  String GET_METHOD = "GET";

  /** Symbolic constant for the POST method. */
  String POST_METHOD = "POST";

  /**
   * Returns the complete URL that the recipient of this instance should use when sending the HTTP
   * request. If the URL has query parameters they are URL-encoded.
   * <p>
   * For a redirect, this URL could look something like:
   * {@code https://www.example.com/result?param=<encoded request>&RelayState=abcd}. For a POST, the
   * URL typically does not include any parameters. Instead these are read using
   * {@link #getHttpParameters()}.
   * </p>
   * <b>Note:</b> Additional query parameters may be added to the URL by the using system.
   *
   * @return the URL to use when sending the request
   */
  String getUrl();

  /**
   * Returns the HTTP method that should be used to send the request, via the user agent, to the
   * recipient (given by {@link #getUrl()}). Possible values for this implementation is "GET"
   * (redirect) and "POST".
   * <p>
   * When "GET" is returned, the message should be sent using a HTTP redirect.
   * </p>
   *
   * @return the HTTP method to use
   */
  String getMethod();

  /**
   * If the {@link #getMethod()} returns "POST" the request should be posted to the recipient along
   * with the parameters supplied by this method. The parameters are represented using a Map where
   * the entries represent parameter names and values.
   * <p>
   * Note: For the "GET" method this method returns the parameters that are part of the URL:s query
   * parameter ({@link #getUrl()}). This means that the service using the object should not include
   * the parameters in the URL. This has already been done.
   * </p>
   * <p>
   * The values in the map are not URL-encoded, so before using any values in the resulting map the
   * values must be encoded.
   * </p>
   *
   * @return a (possibly empty) Map holding the HTTP request parameters
   */
  Map<String, String> getHttpParameters();

  /**
   * Returns a mapping of header names and values that should be used when sending the request.
   *
   * @return a (possibly empty) map of HTTP headers
   */
  Map<String, String> getHttpHeaders();

}
