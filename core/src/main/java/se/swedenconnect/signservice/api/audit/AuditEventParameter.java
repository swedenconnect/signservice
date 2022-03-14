/*
 * Copyright 2022 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package se.swedenconnect.signservice.api.audit;

import java.io.Serializable;
import java.util.Objects;

/**
 * Representation of an audit event parameter, which is a name-value pair.
 */
public class AuditEventParameter implements Serializable {

  /** For serializing. */
  private static final long serialVersionUID = -2737943123086457259L;

  /** The parameter name. */
  private final String name;

  /** The parameter value. */
  private final String value;

  /**
   * Constructor.
   *
   * @param name the parameter name (must not be null)
   * @param value the parameter value (may be null)
   */
  public AuditEventParameter(final String name, final String value) {
    this.name = Objects.requireNonNull(name, "name must not be null");
    this.value = value;
  }

  /**
   * Gets the parameter name.
   *
   * @return the parameter name
   */
  public String getName() {
    return this.name;
  }

  /**
   * Gets the parameter value.
   *
   * @return the parameter value, or null if none has been set
   */
  public String getValue() {
    return this.value;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.name, this.value);
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (this.getClass() != obj.getClass()) {
      return false;
    }
    final AuditEventParameter other = (AuditEventParameter) obj;
    return Objects.equals(this.name, other.name) && Objects.equals(this.value, other.value);
  }


  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("%s='%s'", this.name, this.value);
  }

}
