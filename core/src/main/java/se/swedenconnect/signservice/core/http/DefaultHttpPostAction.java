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
package se.swedenconnect.signservice.core.http;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import javax.annotation.Nonnull;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Default implementation of the {@link HttpPostAction} interface.
 */
public class DefaultHttpPostAction implements HttpPostAction {

  /** The URL where the user should be posted to. */
  private final String url;

  /** The HTTP POST parameters. */
  private final Map<String, String> parameters;

  /**
   * Constructor setting the post URL.
   *
   * @param url the post URL
   */
  @JsonCreator
  public DefaultHttpPostAction(@JsonProperty("url") @Nonnull final String url) {
    this.url = Objects.requireNonNull(url, "url must not be null");
    this.parameters = new HashMap<>();
  }

  /**
   * Gets a {@link HttpPostActionBuilder}.
   *
   * @return a builder
   */
  public static HttpPostActionBuilder builder() {
    return new HttpPostActionBuilder();
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getUrl() {
    return this.url;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public Map<String, String> getParameters() {
    return this.parameters;
  }

  /**
   * Assigns the HTTP post parameters.
   *
   * @param parameters the parameters
   */
  public void setParameters(@Nonnull final Map<String, String> parameters) {
    this.parameters.putAll(Objects.requireNonNull(parameters, "parameters must not be null"));
  }

  /**
   * Adds a HTTP post parameter.
   *
   * @param name the parameter name
   * @param value the parameter value
   */
  public void addParameter(@Nonnull final String name, @Nonnull final String value) {
    this.parameters.put(
        Objects.requireNonNull(name, "name must not be null"),
        Objects.requireNonNull(value, "value must not be null"));
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String toString() {
    return String.format("post[url='%s', parameters=%s]", this.url, this.parameters);
  }

  /**
   * A builder for constructing a {@link HttpPostAction} object.
   */
  public static class HttpPostActionBuilder {

    /** The post action. */
    private DefaultHttpPostAction action;

    /** The HTTP POST parameters. */
    private Map<String, String> parameters;

    /**
     * Builds a {@link HttpPostAction} object.
     *
     * @return a HttpPostAction object
     */
    public HttpPostAction build() {
      return Optional.ofNullable(this.action)
          .orElseThrow(() -> new IllegalArgumentException("No URL assigned"));
    }

    /**
     * Adds the post URL.
     *
     * @param url the post URL
     * @return the builder
     * @throws IllegalArgumentException if the supplied URL is invalid
     */
    public HttpPostActionBuilder url(@Nonnull final String url) throws IllegalArgumentException {

      try {
        // Make sure that this is a valid URL
        this.action = new DefaultHttpPostAction(
            (new URI(Objects.requireNonNull(url, "url must be set"))).toURL().toExternalForm());

        // If parameters were added before the URL was added, add those as well.
        if (this.parameters != null) {
          this.action.setParameters(this.parameters);
          this.parameters = null;
        }
      }
      catch (final URISyntaxException | MalformedURLException e) {
        throw new IllegalArgumentException(e.getMessage(), e);
      }

      return this;
    }

    /**
     * Adds a HTTP parameter.
     *
     * @param name the parameter name
     * @param value the parameter value
     * @return the builder
     */
    public HttpPostActionBuilder parameter(@Nonnull final String name, @Nonnull final String value) {
      if (this.action == null) {
        if (this.parameters == null) {
          this.parameters = new HashMap<>();
        }
        this.parameters.put(
            Objects.requireNonNull(name, "name must not be null"),
            Objects.requireNonNull(value, "value must not be null"));
      }
      else {
        this.action.addParameter(name, value);
      }
      return this;
    }

  }

}
