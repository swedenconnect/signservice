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
package se.swedenconnect.signservice.protocol;

import java.io.Serializable;

/**
 * An interface that represents the processing requirements of a protocol implementation.
 */
public interface ProtocolProcessingRequirements extends Serializable {

  /**
   * An enum that represents the requirement on a message concerning whether is is signed or not.
   */
  public enum SignatureRequirement {
    /** A signature on the message is required. */
    REQUIRED,

    /** Signature on the message is optional. */
    OPTIONAL,

    /** The message should not be signed. */
    NO
  }

  /**
   * Tells the signature requirements for a sign request message.
   *
   * @return a SignatureRequirement
   */
  SignatureRequirement getRequestSignatureRequirement();

  /**
   * Tells the signature requirements for a sign response message.
   *
   * @return a SignatureRequirement
   */
  SignatureRequirement getResponseSignatureRequirement();

  /**
   * Returns the HTTP method to use when sending back a response to the client, for example "POST".
   *
   * @return the HTTP method to use when sending back the response
   */
  String getResponseSendMethod();

}
