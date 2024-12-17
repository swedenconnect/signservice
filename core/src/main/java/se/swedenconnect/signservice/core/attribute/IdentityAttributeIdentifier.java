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
package se.swedenconnect.signservice.core.attribute;

import java.io.Serializable;

/**
 * A generic representation of an identity attribute identifier, i.e. an attribute with no value associated.
 */
public interface IdentityAttributeIdentifier extends Serializable {

  /**
   * Gets the authentication scheme for this attribute representation, e.g., "SAML".
   *
   * @return the "type" of attribute
   */
  String getScheme();

  /**
   * Gets the identifier (name) of the identity attribute.
   *
   * @return the attribute identifier
   */
  String getIdentifier();

  /**
   * Gets the "friendly" name of the attribute, i.e., a human readable representation of the attribute identifier.
   *
   * @return the friendly name, or null if none is available
   */
  String getFriendlyName();

}
