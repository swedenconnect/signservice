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
package se.swedenconnect.signservice.authn;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.core.http.HttpResponseAction;
import se.swedenconnect.signservice.core.types.Choice;

/**
 * Represents the result from an authentication call ({@link AuthenticationHandler}). The result is either an
 * {@link AuthenticationResult} that represents a completed, and successful, authentication or a
 * {@link HttpResponseAction} which is used to indicate to the caller that the user should be directed to remote
 * authentication service.
 */
public class AuthenticationResultChoice extends Choice<HttpResponseAction, AuthenticationResult> {

  /**
   * Constructor setting the {@link HttpResponseAction}.
   *
   * @param responseAction the HTTP response action
   */
  public AuthenticationResultChoice(@Nonnull final HttpResponseAction responseAction) {
    super(responseAction, null);
  }

  /**
   * Constructor setting the {@link AuthenticationResult}.
   *
   * @param authenticationResult the authentication result
   */
  public AuthenticationResultChoice(@Nonnull final AuthenticationResult authenticationResult) {
    super(null, authenticationResult);
  }

  /**
   * Gets the {@link HttpResponseAction}.
   *
   * @return the HTTP response action or null
   */
  @Nullable
  public HttpResponseAction getResponseAction() {
    return this.getFirst();
  }

  /**
   * Gets the {@link AuthenticationResult}.
   *
   * @return the authentication result or null
   */
  @Nullable
  public AuthenticationResult getAuthenticationResult() {
    return this.getSecond();
  }

}
