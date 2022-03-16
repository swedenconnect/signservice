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
package se.swedenconnect.signservice.api.protocol;

import java.io.Serializable;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.swedenconnect.signservice.api.protocol.types.AuthnRequirements;
import se.swedenconnect.signservice.api.protocol.types.MessageConditions;
import se.swedenconnect.signservice.api.protocol.types.SignatureRequirements;
import se.swedenconnect.signservice.api.protocol.types.SigningCertificateRequirements;
import se.swedenconnect.signservice.api.signature.SignatureTask;

/**
 * A generic representation of a signature request message.
 */
public interface SignRequestMessage extends Serializable {

  /**
   * Gets the protocol profile for this type of message.
   *
   * @return a protocol profile
   */
  SignServiceProtocolProfile getProtocolProfile();

  /**
   * Tells whether the message has been signed.
   *
   * @return true if the message is signed, and false otherwise
   */
  boolean isSigned();

  /**
   * Verifies the signature of the message.
   * <p>
   * Invoking this method on a message that is not signed will lead to an error.
   * </p>
   * <p>
   * Note that there is a direct trust regarding expected signing certificates. Thus, the validator
   * does not perform any certificate chain building to find a trusted certificate.
   * </p>
   *
   * @param certificates a list of certificates that are acceptable as signer certificates.
   * @return a SignatureValidationResult object
   * @throws SignatureException for errors during the validation process (pure signature validation
   *         errors are reported in the returned result)
   */
  // TODO: Use a new class. TrustConf...
  SignatureValidationResult verifySignature(final List<X509Certificate> certificates)
      throws SignatureException;

  /**
   * Gets the "relay state" parameter that is associated with the message.
   *
   * @return the relay state parameter, or null if not available
   */
  String getRelayState();

  /**
   * Gets the unique identifier for the request message.
   *
   * @return the request ID
   */
  String getRequestId();

  /**
   * Gets the issuance instant for the message.
   *
   * @return the issuance instant
   */
  Instant getIssuedAt();

  /**
   * Gets the unique identifier of the SignService client that sent this message.
   *
   * @return the client id
   */
  String getClientId();

  /**
   * Gets the URL where the client wants response messages to be sent. This information may also be
   * configured at the SignService.
   *
   * @return the URL, or null if the protocol implementation does not support this feature
   */
  String getResponseUrl();

  /**
   * Gets the SignService ID from the message. This is the ID of the receiving SignService.
   *
   * @return the SignService id
   */
  String getSignServiceId();

  /**
   * Gets the conditions for the message imposed by the issuer.
   *
   * @return conditions, or null if none are available
   */
  MessageConditions getConditions();

  /**
   * Gets the requirements the signature requester (client) puts on how the user should be
   * authenticated during the "authentication for signature" process.
   *
   * @return authentication requirements
   */
  AuthnRequirements getAuthnRequirements();

  /**
   * Gets the Base64-encoded "sign message". The sign message is a protocol specific extension that
   * will be passed on to the authentication service.
   *
   * @return the Base64-encoded sign message, or null if none has been supplied
   */
  String getSignMessage();

  /**
   * Gets the specific signature requirements for this request.
   *
   * @return signature requirements
   */
  SignatureRequirements getSignatureRequirements();

  /**
   * Gets the requirements for how the generated signing certificate should be created.
   *
   * @return signing certificate requirements
   */
  SigningCertificateRequirements getSigningCertificateRequirements();

  /**
   * Gets the signature tasks, i.e., the to-be-signed data.
   *
   * @return a list of signature tasks
   */
  List<SignatureTask> getSignatureTasks();

}
