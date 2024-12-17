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
package se.swedenconnect.signservice.authn.impl;

import java.util.Objects;

import se.swedenconnect.signservice.authn.AuthnContextIdentifier;
import se.swedenconnect.signservice.core.annotations.GeneratedMethod;

/**
 * An implementation of {@link AuthnContextIdentifier} that only handles the identifier.
 */
public class SimpleAuthnContextIdentifier implements AuthnContextIdentifier {

  /** For serializing. */
  private static final long serialVersionUID = 4034387540918163413L;

  /** The authentication context identifier. */
  private final String identifier;

  /**
   * Constructor.
   *
   * @param identifier the authentication context identifier
   */
  public SimpleAuthnContextIdentifier(final String identifier) {
    this.identifier = Objects.requireNonNull(identifier, "identifier must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public String getIdentifier() {
    return this.identifier;
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public int hashCode() {
    return Objects.hash(this.identifier);
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof SimpleAuthnContextIdentifier)) {
      return false;
    }
    final SimpleAuthnContextIdentifier other = (SimpleAuthnContextIdentifier) obj;
    return Objects.equals(this.identifier, other.identifier);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return this.identifier;
  }

}
