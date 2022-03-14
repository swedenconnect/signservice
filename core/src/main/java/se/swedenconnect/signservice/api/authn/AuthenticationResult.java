/*
 * Copyright 2022 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package se.swedenconnect.signservice.api.authn;

import se.swedenconnect.signservice.api.authn.types.IdentityAssertion;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;

/**
 * Represents the result from an authentication call ({@link SignServiceAuthenticationHandler}). The
 * result is either an {@link IdentityAssertion} that represents a completed, and successful,
 * authentication or a HTTP request message which is used to indicate to the caller that the user
 * should be directed to remote authentication service.
 */
public interface AuthenticationResult {

  /**
   * Gets the HTTP request message. This is set if the authentication scheme needs to direct the
   * user to a remote authentication service.
   *
   * @return a HTTP request message
   */
  HttpRequestMessage getHttpRequestMessage();

  /**
   * Gets the {@link IdentityAssertion} that represents a completed, and successful, authentication.
   *
   * @return an identity assertion object
   */
  IdentityAssertion getAssertion();

}
