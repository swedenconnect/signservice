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
package se.swedenconnect.signservice.core.attribute.saml.impl;

import java.time.Instant;
import java.util.List;

/**
 * SAML attribute holding dateTime value(s).
 */
public class InstantSamlIdentityAttribute extends AbstractSamlIdentityAttribute<Instant> {

  /** For serializing. */
  private static final long serialVersionUID = 3590297678033504415L;

  /**
   * Constructor for a single-valued attribute.
   *
   * @param identifier the attribute identifier (name)
   * @param friendlyName the attribute friendly name (optional)
   * @param value the attribute value
   */
  public InstantSamlIdentityAttribute(final String identifier, final String friendlyName, final Instant value) {
    super(identifier, friendlyName, value);
  }

  /**
   * Constructor for a multi-valued attribute.
   *
   * @param identifier the attribute identifier (name)
   * @param friendlyName the attribute friendly name (optional)
   * @param values the attribute values
   */
  public InstantSamlIdentityAttribute(final String identifier, final String friendlyName, final List<Instant> values) {
    super(identifier, friendlyName, values);
  }

  /** {@inheritDoc} */
  @Override
  public Class<Instant> getAttributeValueType() {
    return Instant.class;
  }

}
