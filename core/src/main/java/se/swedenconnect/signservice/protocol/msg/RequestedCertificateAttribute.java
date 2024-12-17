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
package se.swedenconnect.signservice.protocol.msg;

import se.swedenconnect.signservice.certificate.CertificateAttributeIdentifier;

/**
 * Represents a requested certificate attribute. The sign requester states that a given principal attribute should be
 * mapped into a certificate attribute. This class represents how the requirements for certificate attributes are
 * represented.
 */
public interface RequestedCertificateAttribute extends CertificateAttributeIdentifier {

  /**
   * Gets the default value to use if no mapping can be found.
   *
   * @return the value to use if no mapping can be found, or null if no default value has been assigned
   */
  String getDefaultValue();

  /**
   * Indicates if this attribute must be provided.
   *
   * @return tells whether the attribute is required
   */
  boolean isRequired();

}
