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
package se.swedenconnect.signservice.protocol.msg;

import java.io.Serializable;
import java.util.List;

import se.swedenconnect.signservice.core.attribute.IdentityAttributeIdentifier;

/**
 * Describes how a signer's identity attribute(s) are mapped to a certificate attribute to be placed in the issued
 * signature certificate.
 */
public interface CertificateAttributeMapping extends Serializable {

  /**
   * Gets the list of signer source attributes from where the sign service gets information in order to create the
   * requested certificate attribute. If more than one attribute is given, the order is important as the sign service
   * tries the given source attributes in order.
   *
   * @return a list of source attributes
   */
  List<IdentityAttributeIdentifier> getSources();

  /**
   * Gets the requested destination certificate attribute.
   *
   * @return the destination certificate attribute
   */
  RequestedCertificateAttribute getDestination();

}
