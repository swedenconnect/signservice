/*
 * MIT License
 *
 * Copyright 2022 Sweden Connect
 */
package se.swedenconnect.signservice.api.engine;

/**
 * Symbols for "unrecoverable error codes". These kinds of errors are reported back to the
 * application when the engine has no way of constructing an ordinary error response message.
 *
 * @see SignServiceUnrecoverableException
 */
public class UnrecoverableErrorCodes {

  /** Prefix for "unrecoverable" error codes. */
  private static final String ERROR_PREFIX = "error.unrecoverable.";

  /** The client is not not known to the SignService (i.e., is not registered). */
  public static final String UNKNOWN_CLIENT = ERROR_PREFIX + "unknown-client";

  /**
   * A request received from the client could not be validated, i.e., its signature failed to
   * verify.
   */
  public static final String AUTHN_FAILED = ERROR_PREFIX + "authn-failed";

  /** A request received could not be successfully decoded. */
  public static final String PROTOCOL_ERROR = ERROR_PREFIX + "protocol-error";

  // TODO: Define more error codes

  /** Represents an internal SignService error. */
  public static final String INTERNAL_ERROR = ERROR_PREFIX + "internal-error";

  // Hidden constructor.
  private UnrecoverableErrorCodes() {}

}
