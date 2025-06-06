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
package se.swedenconnect.signservice.core.attribute.saml.impl;

import java.util.List;

/**
 * SAML attribute holding boolean value(s).
 */
public class BooleanSamlIdentityAttribute extends AbstractSamlIdentityAttribute<Boolean> {

  /** For serializing. */
  private static final long serialVersionUID = -8233700600956218094L;

  /**
   * Constructor for a single-valued attribute.
   *
   * @param identifier the attribute identifier (name)
   * @param friendlyName the attribute friendly name (optional)
   * @param value the attribute value
   */
  public BooleanSamlIdentityAttribute(final String identifier, final String friendlyName, final Boolean value) {
    super(identifier, friendlyName, value);
  }

  /**
   * Constructor for a multi-valued attribute.
   *
   * @param identifier the attribute identifier (name)
   * @param friendlyName the attribute friendly name (optional)
   * @param values the attribute values
   */
  public BooleanSamlIdentityAttribute(final String identifier, final String friendlyName, final List<Boolean> values) {
    super(identifier, friendlyName, values);
  }

  /** {@inheritDoc} */
  @Override
  public Class<Boolean> getAttributeValueType() {
    return Boolean.class;
  }

}
