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
package se.swedenconnect.signservice.api.signature;

import java.io.Serializable;

/**
 * Representation of a "signature task". A task without a signature is used to represent the data to-be-signed and a
 * task containing a signature represents the result of a signature operation.
 */
public interface SignatureTask extends Serializable {

  /**
   * Gets the unique "sign task ID".
   *
   * @return the identifier for the task
   */
  String getTaskId();

  /**
   * Gets the type of signature.
   *
   * @return the signature type
   */
  SignatureType getSignatureType();

  /**
   * Gets the AdES type requested/produced.
   *
   * @return the AdES type, or null if none is requested/produced
   */
  AdESType getAdESType();

  /**
   * Gets the AdES object requested/produced.
   *
   * @return the AdES object, or null if no AdES object is requested/produced
   */
  AdESObject getAdESObject();

  /**
   * Gets the URI identifying one or more processing rules that the Signing Service MUST apply when processing and using
   * the provided signed information octets.
   *
   * @return processing rules URI or null
   */
  String getProcessingRulesUri();

  /**
   * Gets the raw "to-be-signed" data.
   *
   * @return to-be-signed data
   */
  byte[] getTbsData();

  /**
   * Gets the raw signature bytes. Only present when the task object is present in a response message.
   *
   * @return the signature bytes, or null if no signature is available
   */
  byte[] getSignature();

  /**
   * Gets the signature algorithm identifier (URI) that was used to produce the signature (see {@link #getSignature()}).
   *
   * @return the signature algorithm identifier, or null if no signature is present
   */
  String getSignatureAlgorithmUri();

}
