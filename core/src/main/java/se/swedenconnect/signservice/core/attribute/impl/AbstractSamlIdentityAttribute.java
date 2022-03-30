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
package se.swedenconnect.signservice.core.attribute.impl;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import se.swedenconnect.signservice.core.attribute.SamlIdentityAttribute;

/**
 * Abstract base class for SAML attributes.
 */
public abstract class AbstractSamlIdentityAttribute<T> extends AbstractIdentityAttribute<T>
    implements SamlIdentityAttribute<T> {

  /** The SAML attribute name format. Defaults to {@value #DEFAULT_NAME_FORMAT}. */
  private String nameFormat;

  /** For serializing. */
  private static final long serialVersionUID = -3238197082023939635L;

  /**
   * Constructor for a single-valued attribute.
   *
   * @param identifier the attribute identifier (name)
   * @param friendlyName the attribute friendly name (optional)
   * @param value the attribute value
   */
  public AbstractSamlIdentityAttribute(final String identifier, final String friendlyName, final T value) {
    super("SAML", identifier, friendlyName, value);
  }

  /**
   * Constructor for a multi-valued attribute.
   *
   * @param identifier the attribute identifier (name)
   * @param friendlyName the attribute friendly name (optional)
   * @param values the attribute values
   */
  public AbstractSamlIdentityAttribute(final String identifier, final String friendlyName, final List<T> values) {
    super("SAML", identifier, friendlyName, values);
  }

  /** {@inheritDoc} */
  @Override
  public String getNameFormat() {
    return Optional.ofNullable(this.nameFormat).orElse(DEFAULT_NAME_FORMAT);
  }

  /**
   * Assigns the name format. The default is {@value #DEFAULT_NAME_FORMAT}.
   *
   * @param nameFormat the name format to assign
   */
  public void setNameFormat(final String nameFormat) {
    this.nameFormat = nameFormat;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + Objects.hash(this.getNameFormat());
    return result;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!super.equals(obj)) {
      return false;
    }
    if (!(obj instanceof AbstractSamlIdentityAttribute)) {
      return false;
    }
    final AbstractSamlIdentityAttribute<?> other = (AbstractSamlIdentityAttribute<?>) obj;
    return Objects.equals(this.getNameFormat(), other.getNameFormat());
  }

}
