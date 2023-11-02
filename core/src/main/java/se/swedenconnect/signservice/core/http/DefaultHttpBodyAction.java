/*
 * Copyright 2022-2023 Sweden Connect
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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import jakarta.annotation.Nonnull;

/**
 * Default implementation of {@link HttpBodyAction}.
 */
public class DefaultHttpBodyAction implements HttpBodyAction {

  /** The body contents. */
  private byte[] contents;

  /** The response headers. */
  private Map<String, String> headers = new HashMap<>();

  /**
   * Constructor.
   */
  public DefaultHttpBodyAction() {
  }

  /**
   * Gets a {@link HttpBodyActionBuilder}.
   *
   * @return a builder
   */
  public static HttpBodyActionBuilder builder() {
    return new HttpBodyActionBuilder();
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public byte[] getContents() {
    return this.contents;
  }

  /**
   * Assigns the body contents.
   *
   * @param contents the body
   */
  public void setContents(@Nonnull final byte[] contents) {
    this.contents = Arrays.copyOf(Objects.requireNonNull(contents, "contents must not be null"), contents.length);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public Map<String, String> getHeaders() {
    return Collections.unmodifiableMap(this.headers);
  }

  /**
   * Assigns the response headers. Any potential, existing, headers values may be overwritten.
   *
   * @param headers the headers to set
   */
  public void setHeaders(@Nonnull final Map<String, String> headers) {
    this.headers.putAll(Objects.requireNonNull(headers, "headers must not be null"));
  }

  /**
   * Adds a response header.
   *
   * @param name the header name
   * @param value the header value
   */
  public void addHeader(@Nonnull final String name, @Nonnull final String value) {
    this.headers.put(
        Objects.requireNonNull(name, "name must not be null"),
        Objects.requireNonNull(value, "value must not be null"));
  }

  /**
   * Removes a response header.
   *
   * @param name the header name
   */
  public void removeHeader(@Nonnull final String name) {
    this.headers.remove(Objects.requireNonNull(name, "name must not be null"));
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String toString() {
    return String.format("body[content-length='%d', response-headers=%s]",
        this.contents != null ? this.contents.length : 0, this.headers);
  }

  /**
   * A builder for {@link HttpBodyAction} objects.
   */
  public static class HttpBodyActionBuilder {

    private final DefaultHttpBodyAction bodyAction = new DefaultHttpBodyAction();

    /**
     * Builds a {@link HttpBodyAction} object.
     *
     * @return a HttpBodyAction object
     */
    public HttpBodyAction build() {
      return Optional.of(this.bodyAction)
          .filter(a -> a.getContents() != null)
          .orElseThrow(() -> new IllegalArgumentException("No body contents assigned"));
    }

    /**
     * Assigns the body contents.
     *
     * @param contents the body contents
     * @return the builder
     */
    public HttpBodyActionBuilder contents(@Nonnull final byte[] contents) {
      this.bodyAction.setContents(contents);
      return this;
    }

    /**
     * Adds a response header.
     *
     * @param name the header name
     * @param value the header value
     * @return the builder
     */
    public HttpBodyActionBuilder header(@Nonnull final String name, @Nonnull final String value) {
      this.bodyAction.addHeader(name, value);
      return this;
    }

  }

}
