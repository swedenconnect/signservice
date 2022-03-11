/*
 * MIT License
 *
 * Copyright 2022 Sweden Connect
 */
package se.swedenconnect.signservice.api.protocol;

import java.io.Serializable;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.swedenconnect.signservice.api.protocol.types.MessageConditions;
import se.swedenconnect.signservice.api.session.SignServiceContext;

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
  SignatureValidationResult verifySignature(final List<X509Certificate> certificates)
      throws SignatureException;

  /**
   * Verifies the message against the protocol and its underlying specifications. Such checks can
   * comprise of verifying that the message is not too old.
   *
   * @param context the SignService context
   * @throws SignServiceProtocolException for validation errors
   */
  // TODO: We may want to use an additional excpetion class that could map to errors being reported
  // back to the client.
  void verifyMessage(final SignServiceContext context) throws SignServiceProtocolException;

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

  // TODO: Much more ...
}
