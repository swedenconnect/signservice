/*
 * Copyright 2022 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package se.swedenconnect.signservice.api.certificate.types;

import java.io.Serializable;

/**
 * Representation of the name of a "certificate identity attribute", i.e., identity information that
 * is included in a certificate.
 */
public interface CertificateAttributeName extends Serializable {

  /**
   * Gets the type of the attribute. With type, we mean "where in the certificate will the attribute
   * be placed".
   *
   * @return the type
   */
  CertificateAttributeType getType();

  /**
   * Gets the name of the certificate attribute.
   *
   * @return the attribute name
   */
  String getName();

  /**
   * Gets the "friendly" name of the attribute, i.e., a human readable representation.
   *
   * @return the friendly name, or null if none has been provided
   */
  String getFriendlyName();

}
