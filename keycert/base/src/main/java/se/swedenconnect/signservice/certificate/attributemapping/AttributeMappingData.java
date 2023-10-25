/*
 * Copyright 2022-2023 Sweden Connect
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
package se.swedenconnect.signservice.certificate.attributemapping;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.swedenconnect.signservice.certificate.CertificateAttributeType;

/**
 * Data for a mapped attribute value to be included in a signer certificate.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class AttributeMappingData {

  /**
   * The type of certificate attribute (RDN in subject name, Subject Alt Name (SAN) or Subject Directory Attributes
   * (SDA).
   */
  private CertificateAttributeType certificateAttributeType;

  /**
   * The certificate attribute reference. This is an index of a SAN or the OID string for an attribute.
   */
  private String reference;

  /**
   * The attribute ID of the source assertion attribute.
   */
  private String sourceId;

  /**
   * The friendly name of the assertion attribute.
   */
  private String sourceFriendlyName;

  /**
   * Indicates if the source of the value was a default value from SignRequest and not obtained from the
   * assertion from the identity service
   */
  private boolean defaultValue;

  /**
   * The attribute value.
   */
  private String value;

}
