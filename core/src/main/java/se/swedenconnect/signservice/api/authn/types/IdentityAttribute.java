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
package se.swedenconnect.signservice.api.authn.types;

import java.util.List;

/**
 * A generic representation of an identity attribute.
 *
 * @param <T> the type of attribute values held by this identity attribute
 */
public interface IdentityAttribute<T> extends IdentityAttributeIdentifier {

  /**
   * Gets all attribute values.
   *
   * @return attribute values
   */
  List<T> getValues();

  /**
   * If the attribute is not multi-valued, this method returns the attribute value. If it is, the first value is
   * returned.
   *
   * @return attribute value
   * @see #getValues()
   */
  T getValue();

  /**
   * Tells whether this attribute holds more than one value.
   *
   * @return true if the attribute holds more than one value, and false otherwise
   */
  boolean isMultiValued();

  /**
   * Gets the type of the value(s) held by this attribute.
   *
   * @return the value(s) type
   */
  Class<T> getAttributeValueType();

}
