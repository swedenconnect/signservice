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
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.protocol.msg.SignerAuthnInfo;
import se.swedenconnect.signservice.signature.CompletedSignatureTask;

/**
 * A generic representation of a signature request message.
 * <p>
 * This representation covers both successful and error response messages.
 * </p>
 * <p>
 * Note that the interface defines both getters and setters. The setters are intended for the SignService engine that
 * builds the response message, and even though there is no obvious use for the getters, it would be strange to leave
 * them out. If not, they can be used by logging functions.
 * </p>
 */
public interface SignResponseMessage extends Serializable {

  /**
   * Gets the protocol processing requirements for this type of message.
   *
   * @return processing requirements
   */
  ProtocolProcessingRequirements getProcessingRequirements();

  /**
   * Signs the message using the supplied signing credential.
   * <p>
   * Requirements for how the signature is created is controlled by the protocol itself along with settings in the
   * protocol profile.
   * </p>
   *
   * @param signatureCredential the credential to use when signing
   * @throws SignatureException for signature errors
   */
  void sign(final PkiCredential signatureCredential) throws SignatureException;

  /**
   * Encodes the message according to its protocol to a Base64-encoded string.
   *
   * @return the encoding
   * @throws ProtocolException for encoding errors
   */
  String encode() throws ProtocolException;

  /**
   * Assigns the relay state parameter associated with this message.
   *
   * @param relayState the relay state
   */
  void setRelayState(final String relayState);

  /**
   * Gets the "relay state" parameter that is associated with the message.
   *
   * @return the relay state parameter, or null if not available
   */
  String getRelayState();

  /**
   * Gets the unique identifier for the corresponding request message ({@link SignRequestMessage#getRequestId()}).
   *
   * @return the request ID for the corresponding request message
   */
  String getInResponseTo();

  /**
   * Assigns the unique identifier for the corresponding request message ({@link SignRequestMessage#getRequestId()}).
   *
   * @param requestId the request ID for the corresponding request message
   */
  void setInResponseTo(final String requestId);

  /**
   * Gets the issuance instant for the message.
   *
   * @return the issuance instant
   */
  Instant getIssuedAt();

  /**
   * Assigns the issuance instant for the message.
   * <p>
   * Implementations must default to use the current time if this field is not explicitly assigned.
   * </p>
   *
   * @param issuedAt the issuance instant
   */
  void setIssuedAt(final Instant issuedAt);

  /**
   * Gets the issuer ID for the SignService that issued this response message.
   *
   * @return the issuer ID
   */
  String getIssuerId();

  /**
   * Assigns the issuer ID for the SignService that issued this response message.
   *
   * @param issuerId the issuer ID (SignService ID)
   */
  void setIssuerId(final String issuerId);

  /**
   * Gets the "destination URL", i.e., the URL to where this response message is sent.
   *
   * @return the destination URL
   */
  String getDestinationUrl();

  /**
   * Assigns the "destination URL", i.e., the URL to where this response message is sent.
   *
   * @param destinationUrl the destination URL
   */
  void setDestinationUrl(final String destinationUrl);

  /**
   * Gets the sign response result object.
   *
   * @return the SignResponseResult
   */
  SignResponseResult getSignResponseResult();

  /**
   * Sets the sign response result object.
   *
   * @param signResponseResult the response result
   */
  void setSignResponseResult(final SignResponseResult signResponseResult);

  /**
   * Gets the signer authentication information.
   *
   * @return the authentication information
   */
  SignerAuthnInfo getSignerAuthnInfo();

  /**
   * Assigns the signer authentication information.
   *
   * @param signerAuthnInfo the authentication information
   */
  void setSignerAuthnInfo(final SignerAuthnInfo signerAuthnInfo);

  /**
   * Gets the signature certificate chain, starting with the issued signing certificate, and followed by any CA
   * certificates that can be used to verify the previous certificate in the sequence, ending with a self-signed root
   * certificate.
   *
   * @return the signature certificate chain
   */
  List<X509Certificate> getSignatureCertificateChain();

  /**
   * Assigns the signature certificate chain.
   * <p>
   * The chain must start with the issued signing certificate, and be followed by any CA certificates that can be used
   * to verify the previous certificate in the sequence, and end with a self-signed root certificate.
   * </p>
   *
   * @param chain the signature certificate chain
   */
  void setSignatureCertificateChain(final List<X509Certificate> chain);

  /**
   * Gets the completed signature tasks, i.e. the signed data.
   *
   * @return a list of completed signature tasks
   */
  List<CompletedSignatureTask> getSignatureTasks();

  /**
   * Assigns the completed signature task(s), i.e. the signed data.
   *
   * @param signatureTasks a list of completed signature task(s)
   */
  void setSignatureTasks(final List<CompletedSignatureTask> signatureTasks);

}
