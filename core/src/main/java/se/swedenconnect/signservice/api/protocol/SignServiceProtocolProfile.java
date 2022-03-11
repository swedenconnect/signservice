/*
 * MIT License
 *
 * Copyright 2022 Sweden Connect
 */
package se.swedenconnect.signservice.api.protocol;

import java.io.Serializable;

/**
 * A profile for a SignService protocol.
 */
public interface SignServiceProtocolProfile extends Serializable {

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
   * Gets the name of the SignService protocol profile.
   *
   * @return the name
   */
  String getName();

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

  // TODO: More here

}
