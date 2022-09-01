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
package se.swedenconnect.signservice.protocol.msg;

import java.io.Serializable;

import se.swedenconnect.signservice.authn.IdentityAssertion;

/**
 * Represents information about a signer's authentication.
 */
public interface SignerAuthnInfo extends Serializable {

  /**
   * Gets the identity assertion from the signer authentication.
   * <p>
   * Note that the SignService may choose to include only some of the attributes received in an assertion when passing
   * it back in a response. For integrity reasons it may be desirable to only include the attributes that actually was
   * used (for populating fields in the signer certificate).
   * </p>
   *
   * @return the identity assertion
   */
  IdentityAssertion getIdentityAssertion();

}
