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
package se.swedenconnect.signservice.core.attribute;

/**
 * A converter interface for converting attributes between the generic representation and a specialized attribute
 * representation (OpenSAML, JAXB, ...).
 *
 * @param <T> the type of the specialized attribute representation
 */
public interface AttributeConverter<T> {

  /**
   * Converts the attribute from its generic representation to the specialized representation.
   *
   * @param attribute the attribute to convert
   * @return an attribute object according to the instance's instantiated attribute representation
   * @throws AttributeException for conversion errors
   */
  T convert(final IdentityAttribute<?> attribute) throws AttributeException;

  /**
   * Converts the supplied attribute into its generic representation
   *
   * @param attribute an attribute object according to the instance's instantiated attribute representation
   * @return a generic attribute representation
   * @throws AttributeException for conversion errors
   */
  IdentityAttribute<?> convert(final T attribute) throws AttributeException;

}
