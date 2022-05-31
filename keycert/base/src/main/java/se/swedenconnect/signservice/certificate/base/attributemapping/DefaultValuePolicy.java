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
package se.swedenconnect.signservice.certificate.base.attributemapping;

import javax.annotation.Nonnull;

import se.swedenconnect.signservice.certificate.CertificateAttributeType;

/**
 * Interface for checking if a default value for a certificate attribute is acceptable.
 */
public interface DefaultValuePolicy {

  /**
   * Checks if a default certificate value taken from the sign request is allowed according to the policy of the sign
   * service.
   *
   * @param attributeType type of certificate attribute or subject alt name
   * @param ref id reference of the certificate attribute or subject alt name
   * @param value attribute value
   * @return true if this value is approved for inclusion in the certificate
   */
  boolean isDefaultValueAllowed(
      @Nonnull final CertificateAttributeType attributeType, @Nonnull final String ref, @Nonnull final String value);

}
