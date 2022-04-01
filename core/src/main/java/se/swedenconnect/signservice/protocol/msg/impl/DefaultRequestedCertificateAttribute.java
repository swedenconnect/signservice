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
package se.swedenconnect.signservice.protocol.msg.impl;

import java.util.Objects;
import java.util.Optional;

import se.swedenconnect.signservice.certificate.CertificateAttributeType;
import se.swedenconnect.signservice.certificate.impl.DefaultCertificateAttributeIdentifier;
import se.swedenconnect.signservice.core.annotations.GeneratedMethod;
import se.swedenconnect.signservice.protocol.msg.RequestedCertificateAttribute;

/**
 * Default implementation of the {@link RequestedCertificateAttribute} interface.
 */
public class DefaultRequestedCertificateAttribute extends DefaultCertificateAttributeIdentifier
    implements RequestedCertificateAttribute {

  /** For serializing. */
  private static final long serialVersionUID = 5680298716976736625L;

  /** Optional default value. */
  private String defaultValue;

  /** Whether the attribute is required. */
  private Boolean required;

  /**
   * Constructor.
   *
   * @param type the attribute type (if null, RDN is assumed)
   * @param identifier the attribute identifier (or reference)
   */
  public DefaultRequestedCertificateAttribute(final CertificateAttributeType type, final String identifier) {
    this(type, identifier, null);
  }

  /**
   * Constructor.
   *
   * @param type the attribute type (if null, RDN is assumed)
   * @param identifier the attribute identifier (or reference)
   * @param friendlyName the friendly name (optional)
   */
  public DefaultRequestedCertificateAttribute(
      final CertificateAttributeType type, final String identifier, final String friendlyName) {
    super(Optional.ofNullable(type).orElse(CertificateAttributeType.RDN), identifier, friendlyName);
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
  @GeneratedMethod
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + Objects.hash(this.defaultValue, this.required);
    return result;
  }

  /** {@inheritDoc} */
  @GeneratedMethod
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!super.equals(obj)) {
      return false;
    }
    if (!(obj instanceof DefaultRequestedCertificateAttribute)) {
      return false;
    }
    final DefaultRequestedCertificateAttribute other = (DefaultRequestedCertificateAttribute) obj;
    return Objects.equals(this.defaultValue, other.defaultValue) && Objects.equals(this.required, other.required);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("%s: default-value='%s', required=%s",
        super.toString(), Optional.ofNullable(this.defaultValue).orElse("-"), this.isRequired());
  }

}
