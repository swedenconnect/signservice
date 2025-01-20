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
package se.swedenconnect.signservice.certificate;

import java.util.Optional;

/**
 * Represents the different types, i.e., locations in a certificate where identity information can be inserted.
 */
public enum CertificateAttributeType {

  /**
   * Represents an attribute that is a Relative Distinguished Name in the subject field of the certificate.
   */
  RDN("rdn"),

  /**
   * Represents an attribute that is a value placed in a Subject Alternative Names extension of the certificate.
   */
  SAN("san"),

  /**
   * Represents an attribute that is a value placed in a Subject Directory Attribute extension of the certificate.
   */
  SDA("sda");

  /**
   * Returns the type of certificate attribute.
   *
   * @return the type
   */
  public String getType() {
    return this.type;
  }

  /**
   * Maps the given type to an enum constant.
   *
   * @param type the certificate attribute type
   * @return the enum constant
   * @throws IllegalArgumentException if no constant is matched
   */
  public static CertificateAttributeType fromType(final String type)
      throws IllegalArgumentException {
    for (final CertificateAttributeType t : CertificateAttributeType.values()) {
      if (t.getType().equals(type) || t.name().equals(type)) {
        return t;
      }
    }
    throw new IllegalArgumentException(
        String.format("%s is not a valid CertificateAttributeType", Optional.ofNullable(type).orElse("null")));
  }

  /** The type. */
  private String type;

  /**
   * Constructor.
   *
   * @param type the type
   */
  CertificateAttributeType(final String type) {
    this.type = type;
  }

}
