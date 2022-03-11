/*
 * MIT License
 *
 * Copyright 2022 Sweden Connect
 */
package se.swedenconnect.signservice.api.protocol;

import java.io.Serializable;
import java.security.SignatureException;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * A generic representation of a signature request message.
 */
public interface SignResponseMessage extends Serializable {

  /**
   * Gets the protocol profile for this type of message.
   *
   * @return a protocol profile
   */
  SignServiceProtocolProfile getProtocolProfile();

  /**
   * Signs the message using the supplied signing credential.
   * <p>
   * Requirements for how the signature is created is controlled by the protocol itself along with
   * settings in the protocol profile.
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
   * @throws SignServiceProtocolException for encoding errors
   */
  String encode() throws SignServiceProtocolException;

  /**
   * Assigns the relay state parameter associated with this message.
   * @param relayState the relay state
   */
  void setRelayState(final String relayState);

  /**
   * Gets the "relay state" parameter that is associated with the message.
   *
   * @return the relay state parameter, or null if not available
   */
  String getRelayState();

  // Setters and getters



}
