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
package se.swedenconnect.signservice.core.http.servletapi;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import se.swedenconnect.signservice.core.http.HttpUserRequest;

/**
 * An implementation that wraps a {@link HttpServletRequest} as a {@link HttpUserRequest}.
 * <p>
 * Note: This class can not be used in a frontend/backend deployment where the frontend communicates with the backend
 * over a REST API since it wraps a {@link HttpServletRequest}.
 * </p>
 */
public class ServletApiHttpUserRequest implements HttpUserRequest {

  /** The wrapped HttpServletRequest. */
  private final HttpServletRequest request;

  /**
   * Constructor.
   *
   * @param request the wrapped HttpServletRequest object
   */
  public ServletApiHttpUserRequest(@Nonnull final HttpServletRequest request) {
    this.request = Objects.requireNonNull(request, "request must not be null");
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getMethod() {
    return this.request.getMethod();
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getRequestUrl() {
    return this.request.getRequestURL().toString();
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getServerBaseUrl() {
    final StringBuffer url = new StringBuffer();
    final String scheme = this.request.getScheme();
    url.append(scheme).append("://").append(this.request.getServerName());

    final int port = this.request.getServerPort();
    if ((scheme.equals("http") && port != 80) || (scheme.equals("https") && port != 443)) {
      url.append(':');
      url.append(port);
    }
    url.append(this.request.getContextPath());
    return url.toString();
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getServerServletPath() {
    return this.request.getServletPath();
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getClientIpAddress() {
    return this.request.getRemoteAddr();
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public String getParameter(@Nonnull final String name) {
    return this.request.getParameter(name);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public Map<String, String[]> getParameters() {
    return this.request.getParameterMap();
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public String getHeader(@Nonnull final String name) {
    return this.request.getHeader(name);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public Map<String, String[]> getHeaders() {
    return Collections.list(this.request.getHeaderNames()).stream()
        .map(n -> Map.entry(n, Collections.list(this.request.getHeaders(n)).toArray(String[]::new)))
        .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, Map.Entry::getValue));
  }

}
