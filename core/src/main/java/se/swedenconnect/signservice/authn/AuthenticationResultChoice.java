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
package se.swedenconnect.signservice.authn;

import se.swedenconnect.signservice.core.http.HttpRequestMessage;
import se.swedenconnect.signservice.core.types.Choice;

/**
 * Represents the result from an authentication call ({@link AuthenticationHandler}). The result is either an
 * {@link AuthenticationResult} that represents a completed, and successful, authentication or a HTTP request message
 * which is used to indicate to the caller that the user should be directed to remote authentication service.
 */
public class AuthenticationResultChoice extends Choice<HttpRequestMessage, AuthenticationResult> {

  /**
   * Constructor setting the {@link HttpRequestMessage}.
   *
   * @param httpRequestMessage the HTTP request message
   */
  public AuthenticationResultChoice(final HttpRequestMessage httpRequestMessage) {
    super(httpRequestMessage, null);
  }

  /**
   * Constructor setting the {@link AuthenticationResult}.
   *
   * @param authenticationResult the authentication result
   */
  public AuthenticationResultChoice(final AuthenticationResult authenticationResult) {
    super(null, authenticationResult);
  }

  /**
   * Gets the {@link HttpRequestMessage}.
   *
   * @return the HTTP request message or null
   */
  public HttpRequestMessage getHttpRequestMessage() {
    return this.getFirst();
  }

  /**
   * Gets the {@link AuthenticationResult}.
   *
   * @return the authentication result or null
   */
  public AuthenticationResult getAuthenticationResult() {
    return this.getSecond();
  }

}
