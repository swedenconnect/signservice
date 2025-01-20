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
package se.swedenconnect.signservice.core.attribute.saml;

import se.swedenconnect.signservice.core.attribute.IdentityAttribute;

/**
 * A SAML identity attribute.
 */
public interface SamlIdentityAttribute<T> extends IdentityAttribute<T> {

  /** The default name format to use. */
  String DEFAULT_NAME_FORMAT = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

  /**
   * Returns "SAML".
   */
  @Override
  default String getScheme() {
    return "SAML";
  }

  /**
   * To comply with SAML terminology a {@code getName} method is added. This will always be the same as
   * {@link #getIdentifier()}.
   *
   * @return the attribute name
   */
  default String getName() {
    return this.getIdentifier();
  }

  /**
   * Gets the name format of the SAML attribute.
   *
   * @return the name format
   */
  String getNameFormat();

}
