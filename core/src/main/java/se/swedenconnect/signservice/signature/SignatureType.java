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
package se.swedenconnect.signservice.signature;

/**
 * Representation of the possible signature types.
 */
public enum SignatureType {

  /** XML digital signature. */
  XML("XML"),

  /** PDF signature. */
  PDF("PDF"),

  /** JSON signature. */
  JSON("JSON"),

  /** PKCS#7 signature. */
  CMS("CMS");

  /**
   * Returns the textual representation of the signature type.
   *
   * @return the type
   */
  public String getType() {
    return this.type;
  }

  /**
   * Maps the given type to an enum constant.
   *
   * @param type the textual representation of the signature type
   * @return the enum constant
   * @throws IllegalArgumentException if no constant is matched
   */
  public static SignatureType fromType(final String type)
      throws IllegalArgumentException {
    for (final SignatureType t : SignatureType.values()) {
      if (t.getType().equals(type) || t.name().equals(type)) {
        return t;
      }
    }
    throw new IllegalArgumentException(
        String.format("%s is not a valid SignatureType", type));
  }

  /** The type. */
  private String type;

  /**
   * Constructor.
   *
   * @param type the type
   */
  SignatureType(final String type) {
    this.type = type;
  }

}
