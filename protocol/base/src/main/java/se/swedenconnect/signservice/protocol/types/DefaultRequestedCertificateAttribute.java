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
package se.swedenconnect.signservice.protocol.types;

import java.util.Objects;
import java.util.Optional;

import se.swedenconnect.signservice.api.certificate.types.CertificateAttributeType;
import se.swedenconnect.signservice.api.protocol.types.RequestedCertificateAttribute;

/**
 * Default implementation of the {@link RequestedCertificateAttribute} interface.
 */
public class DefaultRequestedCertificateAttribute implements RequestedCertificateAttribute {

  /** For serializing. */
  private static final long serialVersionUID = 5680298716976736625L;

  /** The certificate type. */
  private final CertificateAttributeType type;

  /** The certificate attribute identifier. */
  private final String identifier;

  /** The attribute friendly name. */
  private String friendlyName;

  /** Optional default value. */
  private String defaultValue;

  /** Whether the attribute is required. */
  private Boolean required;

  /**
   * Constructor.
   *
   * @param type the attribute type
   * @param identifier the attribute identifier (or reference)
   */
  public DefaultRequestedCertificateAttribute(final CertificateAttributeType type, final String identifier) {
    this.type = type;
    this.identifier = Objects.requireNonNull(identifier, "identifier must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public CertificateAttributeType getType() {
    return Optional.ofNullable(this.type).orElse(CertificateAttributeType.RDN);
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

  /**
   * Assigns the friendly name.
   *
   * @param friendlyName the friendly name
   */
  public void setFriendlyName(final String friendlyName) {
    this.friendlyName = friendlyName;
  }

  /** {@inheritDoc} */
  @Override
  public String getDefaultValue() {
    return this.defaultValue;
  }

  /**
   * Assigns the attribute default value.
   *
   * @param defaultValue the default value
   */
  public void setDefaultValue(final String defaultValue) {
    this.defaultValue = defaultValue;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isRequired() {
    return Optional.ofNullable(this.required).orElse(false);
  }

  /**
   * Assigns whether the attribute must be provided.
   *
   * @param required whether the attribute must be provided
   */
  public void setRequired(final Boolean required) {
    this.required = required;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.defaultValue, this.friendlyName, this.identifier, this.required, this.type);
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof RequestedCertificateAttribute)) {
      return false;
    }
    final RequestedCertificateAttribute other = (RequestedCertificateAttribute) obj;
    return Objects.equals(this.defaultValue, other.getDefaultValue())
        && Objects.equals(this.friendlyName, other.getFriendlyName())
        && Objects.equals(this.identifier, other.getIdentifier())
        && Objects.equals(this.isRequired(), other.isRequired())
        && this.getType() == other.getType();
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    if (this.friendlyName != null) {
      return String.format("type=%s, identifier='%s' (%s), default-value='%s', required=%s",
          this.getType(), this.identifier, this.friendlyName, Optional.ofNullable(this.defaultValue).orElse("-"),
          this.isRequired());
    }
    else {
      return String.format("type=%s, identifier='%s', default-value='%s', required=%s",
          this.getType(), this.identifier, Optional.ofNullable(this.defaultValue).orElse("-"), this.isRequired());
    }
  }

}
