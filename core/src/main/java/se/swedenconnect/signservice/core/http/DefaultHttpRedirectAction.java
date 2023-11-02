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

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.hc.core5.net.URLEncodedUtils;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.annotation.Nonnull;

/**
 * Default implementation for the {@link HttpRedirectAction} interface.
 */
@SuppressWarnings("deprecation")
public class DefaultHttpRedirectAction implements HttpRedirectAction {

  /** The redirect URL. */
  private final String url;

  /**
   * Constructor setting the redirect URL.
   *
   * @param url the redirect URL
   */
  @JsonCreator
  public DefaultHttpRedirectAction(@JsonProperty("url") @Nonnull final String url) {
    this.url = Objects.requireNonNull(url, "url must not be null");
  }

  /**
   * Gets a {@link HttpRedirectActionBuilder}.
   *
   * @return a builder
   */
  public static HttpRedirectActionBuilder builder() {
    return new HttpRedirectActionBuilder();
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
  public String toString() {
    return String.format("redirect[url='%s']", this.url);
  }

  /**
   * A builder for constructing a {@link HttpRedirectAction} object.
   */
  public static class HttpRedirectActionBuilder {

    /** The URL where the message is to be sent. */
    private URI uri;

    /** The HTTP parameters. */
    private List<NameValuePair> httpParameters = new ArrayList<>();

    /**
     * Builds a {@link HttpRedirectAction} object.
     *
     * @return a HttpRedirectAction
     */
    public HttpRedirectAction build() {
      if (this.uri == null) {
        throw new IllegalArgumentException("No URL assigned");
      }
      try {
        if (this.httpParameters.isEmpty()) {
          return new DefaultHttpRedirectAction(this.uri.toURL().toExternalForm());
        }
        else {
          final URIBuilder builder = new URIBuilder(this.uri);
          for (final NameValuePair e : this.httpParameters) {
            builder.addParameter(e.getName(), e.getValue());
          }
          return new DefaultHttpRedirectAction(builder.build().toURL().toExternalForm());
        }
      }
      catch (final MalformedURLException | URISyntaxException e) {
        // We have already made sure that the URL we are working with is a valid
        // URL, so this can never happen ...
        throw new RuntimeException(e);
      }
    }

    /**
     * Adds the redirect URL.
     *
     * @param url the redirect URL
     * @return the builder
     * @throws IllegalArgumentException if the supplied URL is invalid
     */
    public HttpRedirectActionBuilder url(@Nonnull final String url) throws IllegalArgumentException {

      try {
        this.uri = new URI(Objects.requireNonNull(url, "url must be set"));

        // OK, it's a valid URI, but we also want to make sure that it is a valid URL ...
        this.uri.toURL();

        // If the URL has query parameters move them from the internal URI to the HTTP parameters ...
        //
        final List<NameValuePair> params = URLEncodedUtils.parse(this.uri.getQuery(), Charset.forName("UTF-8"));
        if (!params.isEmpty()) {
          params.stream().forEach(p -> this.httpParameters.add(new BasicNameValuePair(p.getName(), p.getValue())));

          this.uri = new URI(this.uri.getScheme(), this.uri.getUserInfo(), this.uri.getHost(), this.uri.getPort(),
              this.uri.getPath(), null, this.uri.getFragment());
        }
      }
      catch (final URISyntaxException | MalformedURLException e) {
        throw new IllegalArgumentException(e.getMessage(), e);
      }

      return this;
    }

    /**
     * Adds a HTTP parameter (will be added as a query parameter to the redirect URL).
     *
     * @param name the parameter name
     * @param value the parameter value
     * @return the builder
     */
    public HttpRedirectActionBuilder parameter(@Nonnull final String name, @Nonnull final String value) {
      this.httpParameters.add(new BasicNameValuePair(
          Objects.requireNonNull(name, "name must not be null"),
          Objects.requireNonNull(value, "value must not be null")));
      return this;
    }

  }

}
