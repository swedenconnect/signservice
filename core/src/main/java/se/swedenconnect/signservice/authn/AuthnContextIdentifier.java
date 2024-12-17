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
package se.swedenconnect.signservice.authn;

import java.io.Serializable;

/**
 * A representation of an "Authentication Context Identifier". This identifier is often referred to as the "level of
 * assurance" (LoA), and represented as an URI. But since the SignService Core API:s are generic it is not directly
 * represented as a String.
 */
public interface AuthnContextIdentifier extends Serializable {

  /**
   * Gets the authentication context identifier.
   *
   * @return the identifier
   */
  String getIdentifier();

}
