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

import java.io.Serializable;

/**
 * Representation of an AdES object.
 *
 * <p>
 *   The AdES Object is an optional object that carries AdES information associated with a signature.
 *   This is relevant for XAdES signatures where the AdES data is provided in an XMLSignature object.
 *   The type of data provided in the AdES object is defined by each signature type.
 * </p>
 */
public interface AdESObject extends Serializable {

  /**
   * The ID of the signature this AdESObject is associated with if relevant.
   *
   * <p>
   *   Some AdES profiles requires the AdES object to refer to the signature it is associated with. This is
   *   relevant for XAdES signatures.
   * </p>
   *
   * @return The ID of the associated signature
   */
  String getSignatureId();

  /**
   * Getter for AdES object data
   *
   * @return AdES object data
   */
  byte[] getObjectBytes();

}
