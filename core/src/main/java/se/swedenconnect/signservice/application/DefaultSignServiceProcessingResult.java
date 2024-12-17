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
package se.swedenconnect.signservice.application;

import java.util.Objects;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.http.HttpResponseAction;

/**
 * Default implementation of the {@link SignServiceProcessingResult} interface.
 */
public class DefaultSignServiceProcessingResult implements SignServiceProcessingResult {

  /** The SignService context. */
  private final SignServiceContext context;

  /** The response action. */
  private final HttpResponseAction responseAction;

  /**
   * Constructor.
   *
   * @param context the context (may be null)
   * @param responseAction the response action
   */
  public DefaultSignServiceProcessingResult(
      @Nullable final SignServiceContext context,
      @Nonnull final HttpResponseAction responseAction) {
    this.context = context;
    this.responseAction = Objects.requireNonNull(responseAction, "responseAction must not be null");
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public SignServiceContext getSignServiceContext() {
    return this.context;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public HttpResponseAction getResponseAction() {
    return this.responseAction;
  }

}
