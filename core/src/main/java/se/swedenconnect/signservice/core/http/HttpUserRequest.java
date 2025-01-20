/*
 * Copyright 2022-2025 Sweden Connect
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
package se.swedenconnect.signservice.core.http;

import java.util.Map;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

/**
 * Representation of the HTTP request message that is received by the SignService application/frontend.
 * <p>
 * In cases where the SignService deployment is a combined front- and backend the {@code HttpUserRequest} will be a
 * direct mapping of the incoming HTTP request. If the SignService deployment consists of a frontend and a backend, the
 * frontend application needs to translate the incoming HTTP request into a {@code HttpUserRequest} instance that can be
 * transfered between the front- and backend (for example in a REST API-call).
 * </p>
 */
@JsonDeserialize(as = DefaultHttpUserRequest.class)
public interface HttpUserRequest {

  /**
   * Gets the HTTP method with which this request was made (i.e., {@code GET}, {@code POST}, {@code PUT}, ...).
   *
   * @return name of HTTP method used to send the request
   */
  @Nonnull
  String getMethod();

  /**
   * Gets the complete request URL of the user HTTP request that was received by the frontend. This includes the
   * protocol, host, (port), context path and servlet path. This string does not include any potential query parameters.
   *
   * @return complete request URL
   */
  @Nonnull
  String getRequestUrl();

  /**
   * Gets the frontend "server base URL", which is the protocol, host and context path.
   *
   * @return the frontend server base URL
   */
  @Nonnull
  String getServerBaseUrl();

  /**
   * Gets the part of this request's URL that calls the frontend's servlet. This path starts with a "/" character and
   * includes either the servlet name or a path to the servlet, but does not include any extra path information or a
   * query string.
   *
   * <p>
   * This method will return an empty string ("") if the servlet used to process this request was matched using the "/*"
   * pattern.
   * </p>
   *
   * @return the frontend's servlet path that matched this request
   */
  @Nonnull
  String getServerServletPath();

  /**
   * Gets the client IP address.
   *
   * @return the client IP addres
   */
  @Nonnull
  String getClientIpAddress();

  /**
   * Gets the value of a request parameter as a string, or {@code null} if the parameter does not exist.
   * <p>
   * Request parameters are extra information sent with the request. For HTTP servlets, parameters are contained in the
   * query string or posted form data.
   * </p>
   * <p>
   * In case you know, or want to be sure, that the parameter contains multiple values, use {@link #getParameters()}.
   * </p>
   *
   * @param name the parameter name
   * @return the parameter value, or null if it does not exist
   * @see #getParameters()
   */
  @Nullable
  String getParameter(@Nonnull final String name);

  /**
   * Gets a map of all request parameters, where the map entry key is the parameter name and the map entry value(s) is
   * the parameter value.
   * <p>
   * Request parameters are extra information sent with the request. For HTTP servlets, parameters are contained in the
   * query string or posted form data.
   * </p>
   *
   * @return a map (possibly empty) of parameter names and values
   * @see #getParameter(String)
   */
  @Nonnull
  Map<String, String[]> getParameters();

  /**
   * Gets the value of the specified request header. If the request did not include a header of the specified name, this
   * method returns {@code null}.
   * <p>
   * If there are multiple headers with the same name, this method returns the first header value in the request.
   * </p>
   * <p>
   * Note: The header name is case insensitive.
   * </p>
   *
   * @param name the header name
   * @return the header value, or null
   * @see #getHeaders()
   */
  @Nullable
  String getHeader(@Nonnull final String name);

  /**
   * Gets a map of all request headers where the map entry key is the header name and the map entry value is the header
   * value(s).
   *
   * @return a (possibly empty) map of header names and values
   * @see #getHeader(String)
   */
  @Nonnull
  Map<String, String[]> getHeaders();

}
