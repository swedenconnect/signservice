/*
 * Copyright 2022-2024 Sweden Connect
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

import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

/**
 * Default implementation of the {@link HttpResponseAction} interface.
 */
@JsonInclude(Include.NON_NULL)
@JsonDeserialize(using = DefaultHttpResponseActionDeserializer.class)
public class DefaultHttpResponseAction implements HttpResponseAction {

  /** Redirect action. */
  private final HttpRedirectAction redirect;

  /** Post action. */
  private final HttpPostAction post;

  /** Response body action. */
  private final HttpBodyAction body;

  /**
   * Constructor setting up the {@link HttpResponseAction} with a redirect action.
   *
   * @param redirect the redirect action
   */
  public DefaultHttpResponseAction(@Nonnull final HttpRedirectAction redirect) {
    this.redirect = Objects.requireNonNull(redirect, "redirect must not be null");
    this.post = null;
    this.body = null;
  }

  /**
   * Constructor setting up the {@link HttpResponseAction} with a post action.
   *
   * @param post the post action
   */
  public DefaultHttpResponseAction(@Nonnull final HttpPostAction post) {
    this.redirect = null;
    this.post = Objects.requireNonNull(post, "post must not be null");
    this.body = null;
  }

  /**
   * Constructor setting up the {@link HttpResponseAction} with a response body action.
   *
   * @param body the response body action
   */
  public DefaultHttpResponseAction(@Nonnull final HttpBodyAction body) {
    this.redirect = null;
    this.post = null;
    this.body = Objects.requireNonNull(body, "body must not be null");
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public HttpRedirectAction getRedirect() {
    return this.redirect;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public HttpPostAction getPost() {
    return this.post;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public HttpBodyAction getBody() {
    return this.body;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String toString() {
    return this.redirect != null
        ? this.redirect.toString()
        : this.post != null
            ? this.post.toString()
            : this.body.toString();
  }

}
