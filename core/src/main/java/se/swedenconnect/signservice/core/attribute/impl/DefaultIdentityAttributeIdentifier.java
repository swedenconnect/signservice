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
package se.swedenconnect.signservice.core.attribute.impl;

import java.util.Objects;

import se.swedenconnect.signservice.core.annotations.GeneratedMethod;
import se.swedenconnect.signservice.core.attribute.IdentityAttributeIdentifier;

/**
 * Default implementation of the {@link IdentityAttributeIdentifier} interface.
 */
public class DefaultIdentityAttributeIdentifier implements IdentityAttributeIdentifier {

  /** For serializing. */
  private static final long serialVersionUID = -1079719193282030574L;

  /** The scheme, or type, of attribute. */
  private final String scheme;

  /** The attribute identifier (name). */
  private final String identifier;

  /** The attribute friendly name (optional). */
  private final String friendlyName;

  /**
   * Constructor.
   *
   * @param scheme the scheme, or type, of attribute
   * @param identifier the attribute identifier (name)
   * @param friendlyName the attribute friendly name (optional)
   */
  public DefaultIdentityAttributeIdentifier(final String scheme, final String identifier, final String friendlyName) {
    this.scheme = Objects.requireNonNull(scheme, "scheme must not be null");
    this.identifier = Objects.requireNonNull(identifier, "identifier must not be null");
    this.friendlyName = friendlyName;
  }

  /** {@inheritDoc} */
  @Override
  public String getScheme() {
    return this.scheme;
  }

  /** {@inheritDoc} */
  @Override
  public String getIdentifier() {
    return this.identifier;
  }

  /** {@inheritDoc} */
  @Override
  public String getFriendlyName() {
    return this.friendlyName;
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public int hashCode() {
    return Objects.hash(this.identifier, this.scheme);
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof DefaultIdentityAttributeIdentifier)) {
      return false;
    }
    final DefaultIdentityAttributeIdentifier other = (DefaultIdentityAttributeIdentifier) obj;
    return Objects.equals(this.identifier, other.identifier) && Objects.equals(this.scheme, other.scheme);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    if (this.friendlyName != null) {
      return String.format("[%s] %s (%s)", this.scheme, this.identifier, this.friendlyName);
    }
    else {
      return String.format("[%s] %s", this.scheme, this.identifier);
    }
  }

}
