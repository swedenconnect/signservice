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

/**
 * Represents the result from a successful and completed authentication call.
 */
public interface AuthenticationResult {

  /**
   * Gets the {@link IdentityAssertion} that holds the identity assertion from the authentication process.
   *
   * @return an identity assertion object
   */
  IdentityAssertion getAssertion();

  /**
   * Predicate that tells whether the sign message was display to the user during authentication.
   *
   * @return true if the sign message was display, and false otherwise
   */
  boolean signMessageDisplayed();

}