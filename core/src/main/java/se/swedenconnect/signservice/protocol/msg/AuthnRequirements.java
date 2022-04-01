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
import java.util.List;

import se.swedenconnect.signservice.authn.AuthnContextIdentifier;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;

/**
 * Representation of the authentication requirements. This means the requirements the client puts on how the user should
 * be "authenticated for signing".
 */
public interface AuthnRequirements extends Serializable {

  /**
   * Gets the identity of the authentication service (Identity Provider, OpenID provider, ...) that will authenticate
   * the signer as part of the signature process.
   *
   * <p>
   * In almost all cases a user is first authenticated before performing a signature, and the identity is then the ID of
   * the authentication service that authenticated the user during login to the service requesting the signature.
   * </p>
   * <p>
   * In the rare cases where a user is not authenticated when the signature is requested, it is the signature
   * requester's (i.e., the client) responsibility to prompt the user for the authentication service to use, or by other
   * means acquire this information.
   * </p>
   *
   * @return the ID of the authentication service to use
   */
  String getAuthnServiceID();

  /**
   * Gets the "authentication profile". This is an opaque string that can be used to inform the Signing Service about
   * specific requirements regarding the user authentication at the given authentication service.
   *
   * @return opaque string representing an authentication profile
   */
  String getAuthnProfile();

  /**
   * Gets the authentication context identifier(s) that identifies the context under which the signer should be
   * authenticated. This identifier is often referred to as the "level of assurance" (LoA).
   * <p>
   * In the normal case where the user already has been authenticated, the authentication context reference identifier
   * received from the authentication process should be used.
   * </p>
   * <p>
   * If several URI:s are supplied it states that the Signature Service should assert that the user is authenticated
   * according to one of the supplied URI:s.
   * </p>
   *
   * @return the authentication context identifiers
   */
  List<AuthnContextIdentifier> getAuthnContextIdentifiers();

  /**
   * Gets a list of identity attribute values that the sign requestor (client) requires the authentication service to
   * validate and deliver (and the signature service to assert).
   * <p>
   * Typically, a sign requester includes the identity attributes that binds the signature operation to the principal
   * that authenticated at the sign requester service, for example the personalIdentityNumber of the principal.
   * </p>
   *
   * @return a list of requested identity attribute values
   */
  List<IdentityAttribute<?>> getRequestedSignerAttributes();

}
