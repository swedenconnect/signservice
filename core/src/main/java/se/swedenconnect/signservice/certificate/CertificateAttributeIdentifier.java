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
package se.swedenconnect.signservice.certificate;

import java.io.Serializable;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

/**
 * Representation of the identifier of a "certificate identity attribute", i.e., identity information that is included
 * in a certificate.
 */
public interface CertificateAttributeIdentifier extends Serializable {

  /**
   * Gets the type of the attribute. With type, we mean "where in the certificate will the attribute be placed".
   *
   * @return the type
   */
  @Nonnull
  CertificateAttributeType getType();

  /**
   * Gets the identifier (name) of the certificate attribute.
   * <p>
   * This identifier is a reference to the certificate attribute or name type where the requester wants to store this
   * attribute value. The information in this attribute depends on the {@link CertificateAttributeType} value. If the
   * type is "rdn" or "sda", then this attribute MUST contain a string representation of an object identifier (OID). If
   * the type is "san" (Subject Alternative Name) and the target name is a GeneralName, then this identifier MUST hold a
   * string representation of the tag value of the target GeneralName type, e.g. "1" for rfc822Name (e-mail), "2" for
   * dNSName and so on.
   * </p>
   * <p>
   * Representation of an OID as a string in this attribute MUST consist of a sequence of integers delimited by a dot.
   * This string MUST not contain white space or line breaks. Example: "2.5.4.32".
   * </p>
   *
   * @return the attribute identifier
   */
  @Nonnull
  String getIdentifier();

  /**
   * Gets the "friendly" name of the attribute, i.e., a human readable representation.
   *
   * @return the friendly name, or null if none has been provided
   */
  @Nullable
  String getFriendlyName();

}
