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
package se.swedenconnect.signservice.certificate.impl;

import java.util.Objects;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.certificate.CertificateAttributeIdentifier;
import se.swedenconnect.signservice.certificate.CertificateAttributeType;
import se.swedenconnect.signservice.core.annotations.GeneratedMethod;

/**
 * Default implementation of the {@link CertificateAttributeIdentifier} interface.
 */
public class DefaultCertificateAttributeIdentifier implements CertificateAttributeIdentifier {

  // For serializing
  private static final long serialVersionUID = -3389737202407629551L;

  // The type of attribute
  private final CertificateAttributeType type;

  // The attribute identifier
  private final String identifier;

  // The attribute friendly name
  private final String friendlyName;

  /**
   * Constructor.
   *
   * @param type the type of attribute
   * @param identifier the attribute identifier (name)
   */
  public DefaultCertificateAttributeIdentifier(
      @Nonnull final CertificateAttributeType type, @Nonnull final String identifier) {
    this(type, identifier, null);
  }

  /**
   * Constructor.
   *
   * @param type the type of attribute
   * @param identifier the attribute identifier (name)
   * @param friendlyName the attribute friendly name (optional)
   */
  public DefaultCertificateAttributeIdentifier(@Nonnull final CertificateAttributeType type,
      @Nonnull final String identifier, @Nullable final String friendlyName) {
    this.type = Objects.requireNonNull(type, "type must not be null");
    this.identifier = Optional.ofNullable(identifier).filter(StringUtils::isNotBlank)
        .orElseThrow(() -> new IllegalArgumentException("identifier must not be null or blank"));
    this.friendlyName = friendlyName;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public CertificateAttributeType getType() {
    return this.type;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getIdentifier() {
    return this.identifier;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public String getFriendlyName() {
    return this.friendlyName;
  }

  /** {@inheritDoc} */
  @GeneratedMethod
  @Override
  public int hashCode() {
    return Objects.hash(this.friendlyName, this.identifier, this.type);
  }

  /** {@inheritDoc} */
  @GeneratedMethod
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof DefaultCertificateAttributeIdentifier)) {
      return false;
    }
    final DefaultCertificateAttributeIdentifier other = (DefaultCertificateAttributeIdentifier) obj;
    return Objects.equals(this.identifier, other.identifier) && this.type == other.type;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final String s = String.format("[%s] %s", this.type, this.identifier);
    if (this.friendlyName != null) {
      return String.format("%s (%s)", s, this.friendlyName);
    }
    else {
      return s;
    }
  }

}
