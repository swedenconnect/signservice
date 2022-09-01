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

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

import javax.annotation.Nonnull;

import se.swedenconnect.signservice.core.attribute.IdentityAttribute;

/**
 * Represents an identity assertion.
 */
public interface IdentityAssertion extends Serializable {

  /**
   * Gets the authentication scheme for this assertion, e.g., "SAML".
   *
   * @return the "type" of assertion
   */
  @Nonnull
  String getScheme();

  /**
   * Gets the identifier for the assertion.
   *
   * @return the assertion ID
   */
  @Nonnull
  String getIdentifier();

  /**
   * Gets the issuer identity of the authentication assertion.
   *
   * @return the ID of the authentication service that authenticated the user
   */
  @Nonnull
  String getIssuer();

  /**
   * Gets the instant when this assertion was issued.
   *
   * @return the assertion issuance time
   */
  @Nonnull
  Instant getIssuanceInstant();

  /**
   * Gets the instant when the user was authenticated.
   *
   * @return the authentication instant
   */
  @Nonnull
  Instant getAuthnInstant();

  /**
   * Gets the authentication context under which the authentication was made.
   *
   * @return the authentication context
   */
  @Nonnull
  AuthnContextIdentifier getAuthnContext();

  /**
   * Gets the identity attributes.
   *
   * @return the identity attributes (may be an empty list)
   */
  @Nonnull
  List<IdentityAttribute<?>> getIdentityAttributes();

  /**
   * Gets the encoding of the assertion.
   *
   * @return the encoding of the assertion
   */
  @Nonnull
  byte[] getEncodedAssertion();

}
