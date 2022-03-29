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

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import se.swedenconnect.signservice.core.attribute.IdentityAttribute;

/**
 * An abstract base class for {@link IdentityAttribute}.
 *
 * @param <T> the attribute value type
 */
public abstract class AbstractIdentityAttribute<T> extends DefaultIdentityAttributeIdentifier
    implements IdentityAttribute<T> {

  /** For serializing. */
  private static final long serialVersionUID = -8588249704287975256L;

  /** The attribute value(s). */
  private final List<T> values;

  /**
   * Constructor for a single-valued attribute.
   *
   * @param scheme the scheme, or type, of attribute
   * @param identifier the attribute identifier (name)
   * @param friendlyName the attribute friendly name (optional)
   * @param value the attribute value
   */
  public AbstractIdentityAttribute(final String scheme, final String identifier, final String friendlyName,
      final T value) {
    this(scheme, identifier, friendlyName,
        Arrays.asList(Objects.requireNonNull(value, "value must not be null")));
  }

  /**
   * Constructor for a multi-valued attribute.
   *
   * @param scheme the scheme, or type, of attribute
   * @param identifier the attribute identifier (name)
   * @param friendlyName the attribute friendly name (optional)
   * @param values the attribute values
   */
  public AbstractIdentityAttribute(final String scheme, final String identifier, final String friendlyName,
      final List<T> values) {
    super(scheme, identifier, friendlyName);
    this.values = Objects.requireNonNull(values, "values must not be null");
    if (this.values.isEmpty()) {
      throw new IllegalArgumentException("At least one attribute value must be given");
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<T> getValues() {
    return this.values;
  }

  /** {@inheritDoc} */
  @Override
  public T getValue() {
    return this.values.get(0);
  }

  /** {@inheritDoc} */
  @Override
  public boolean isMultiValued() {
    return this.values.size() > 1;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = super.hashCode();
    result = prime * result + Objects.hash(this.values);
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
    if (!(obj instanceof AbstractIdentityAttribute)) {
      return false;
    }
    final AbstractIdentityAttribute<?> other = (AbstractIdentityAttribute<?>) obj;
    return Objects.equals(this.values, other.values);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    if (this.values.size() == 1) {
      return String.format("%s: %s", this.values.get(0));
    }
    else {
      return String.format("%s: %s", this.values);
    }
  }

}
