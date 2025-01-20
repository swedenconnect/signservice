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

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.Setter;

/**
 * Default implementation of the {@link HttpUserRequest} interface. Its primary use is in frontend/backup deployments
 * where it can help serializing/deserializing to and from JSON.
 */
@JsonInclude(Include.NON_NULL)
public class DefaultHttpUserRequest implements HttpUserRequest {

  /** The HTTP method. */
  @Setter
  private String method;

  /**
   * The complete request URL of the user HTTP request that was received by the frontend. This includes the protocol,
   * host, (port), context path and servlet path. This string does not include any potential query parameters.
   */
  @Setter
  private String requestUrl;

  /** The frontend "server base URL", which is the protocol, host and context path. */
  @Setter
  private String serverBaseUrl;

  /**
   * The part of this request's URL that calls the frontend's servlet. This path starts with a "/" character and
   * includes either the servlet name or a path to the servlet, but does not include any extra path information or a
   * query string.
   */
  @Setter
  private String serverServletPath;

  /** The client IP address. */
  @Setter
  private String clientIpAddress;

  /**
   * A map of all request parameters, where the map entry key is the parameter name and the map entry value(s) is the
   * parameter value.
   */
  @Setter
  private Map<String, String[]> parameters;

  /**
   * A map of all request headers where the map entry key is the header name and the map entry value is the header
   * value(s).
   */
  @Setter
  private Map<String, String[]> headers;

  /**
   * Default constructor.
   */
  public DefaultHttpUserRequest() {
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getMethod() {
    return this.method;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getRequestUrl() {
    return this.requestUrl;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getServerBaseUrl() {
    return this.serverBaseUrl;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getServerServletPath() {
    return this.serverServletPath;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getClientIpAddress() {
    return this.clientIpAddress;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public String getParameter(@Nonnull final String name) {
    return Optional.ofNullable(this.parameters)
        .map(p -> p.get(name))
        .filter(a -> a.length > 0)
        .map(a -> a[0])
        .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public Map<String, String[]> getParameters() {
    return Optional.ofNullable(this.parameters)
        .orElseGet(() -> Collections.emptyMap());
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public String getHeader(@Nonnull final String name) {
    return Optional.ofNullable(this.headers)
        .map(h -> h.get(name))
        .filter(a -> a.length > 0)
        .map(a -> a[0])
        .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public Map<String, String[]> getHeaders() {
    return Optional.ofNullable(this.headers)
        .orElseGet(() -> Collections.emptyMap());
  }

}
