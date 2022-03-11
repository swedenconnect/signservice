/*
 * MIT License
 *
 * Copyright 2022 Sweden Connect
 */
package se.swedenconnect.signservice.core.http;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;

/**
 * Default implementation for {@link HttpRequestMessage}.
 */
public class DefaultHttpRequestMessage implements HttpRequestMessage {

  /** The HTTP method. */
  private final String method;

  /** The URL where the message is to be sent. */
  private URI uri;

  /** The HTTP parameters. */
  private List<NameValuePair> httpParameters;

  /** The HTTP headers. */
  private Map<String, String> httpHeaders;

  /**
   * Constructor setting the HTTP method and the URL.
   * <p>
   * If the method is GET it is possible to add additional parameters using
   * {@link #addHttpParameter(String, String)}. These will be URL-encoded and added to the resulting
   * URL (returned from {@link #getUrl()}).
   * </p>
   * <p>
   * If the method is POST and the supplied URL contains query parameters, they will not be
   * interpreted as parameters that should be included in the POST body (i.e., be returned from
   * {@link #getHttpParameters()}).
   * </p>
   *
   * @param method the HTTP method
   * @param url the URL
   * @throws IllegalArgumentException if the supplied URL is invalid
   */
  public DefaultHttpRequestMessage(final String method, final String url)
      throws IllegalArgumentException {

    this.method = Optional.ofNullable(method)
        .map(String::strip)
        .map(String::toUpperCase)
        .filter(s -> !s.isEmpty())
        .orElseThrow(() -> new IllegalArgumentException("method must be set"));

    // We only support GET and POST
    if (!GET_METHOD.equals(this.method) && !POST_METHOD.equals(this.method)) {
      throw new IllegalArgumentException("Unsupported method - " + this.method);
    }

    try {
      this.uri = new URI(Objects.requireNonNull(url, "url must be set"));

      // OK, it's a valid URI, but we also want to make sure that it is a valid URL ...
      this.uri.toURL();

      // If this is a GET request and the URL has query parameters move them
      // from the internal URI to the HTTP parameters ...
      //
      if (GET_METHOD.equals(this.method)) {
        final List<NameValuePair> params =
            URLEncodedUtils.parse(this.uri.getQuery(), Charset.forName("UTF-8"));
        if (!params.isEmpty()) {
          this.httpParameters = new ArrayList<NameValuePair>();
          params.stream().forEach(
              p -> this.httpParameters.add(new BasicNameValuePair(p.getName(), p.getValue())));

          this.uri = new URI(this.uri.getScheme(), this.uri.getUserInfo(), this.uri.getHost(),
              this.uri.getPort(), this.uri.getPath(), null, this.uri.getFragment());
        }
      }
    } catch (final URISyntaxException | MalformedURLException e) {
      throw new IllegalArgumentException(e.getMessage(), e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public String getUrl() {
    try {
      if (GET_METHOD.equals(this.method)) {
        if (this.httpParameters == null || this.httpParameters.isEmpty()) {
          return this.uri.toURL().toExternalForm();
        } else {
          final URIBuilder builder = new URIBuilder(this.uri);
          for (final NameValuePair e : this.httpParameters) {
            builder.addParameter(e.getName(), e.getValue());
          }
          return builder.build().toURL().toExternalForm();
        }
      } else {
        return this.uri.toURL().toExternalForm();
      }
    } catch (final MalformedURLException | URISyntaxException e) {
      // We have already made sure that the URL we are working with is a valid
      // URL, so this can never happen ...
      throw new RuntimeException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public String getMethod() {
    return this.method;
  }

  /** {@inheritDoc} */
  @Override
  public Map<String, String> getHttpParameters() {
    return this.httpParameters != null
        ? this.httpParameters.stream()
            .collect(Collectors.toMap(NameValuePair::getName, NameValuePair::getValue))
        : Collections.emptyMap();
  }

  /**
   * Adds a HTTP parameter.
   * <p>
   * The supplied value <b>must not</b> be URL-encoded (RFC3986 or RFC2396).
   * </p>
   * <p>
   * The order in which the parameters are added will be preserved if the method is GET and the
   * parameters are made into query parameters.
   * </p>
   *
   * @param name the name of the HTTP parameter
   * @param value the value of the HTTP parameter
   */
  public void addHttpParameter(final String name, final String value) {
    // Just to be sure. URL-decode the value.
    // This only covers RFC3986 and not RFC2396 (that uses '+' for spaces), but
    // hey, we told the user in the comment to not pass in a URL-encoded value.
    //
    final String checkedValue = URLDecoder.decode(value, StandardCharsets.UTF_8);

    if (this.httpParameters == null) {
      this.httpParameters = new ArrayList<>();
    }
    this.httpParameters.add(new BasicNameValuePair(name, checkedValue));
  }

  /** {@inheritDoc} */
  @Override
  public Map<String, String> getHttpHeaders() {
    return this.httpHeaders != null ? this.httpHeaders : Collections.emptyMap();
  }

  /**
   * Adds a HTTP header.
   *
   * @param name the header name
   * @param value the header value
   */
  public void addHttpHeader(final String name, final String value) {
    if (this.httpHeaders == null) {
      this.httpHeaders = new HashMap<>();
    }
    this.httpHeaders.put(name, value);
  }

}
