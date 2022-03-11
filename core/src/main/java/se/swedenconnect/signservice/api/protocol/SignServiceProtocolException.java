/*
 * MIT License
 *
 * Copyright 2022 Sweden Connect
 */
package se.swedenconnect.signservice.api.protocol;

/**
 * Exception class for SignService protocol related errors such as decode and encode errors.
 */
public class SignServiceProtocolException extends Exception {

  /** For serializing. */
  private static final long serialVersionUID = -5712026664663974469L;

  /**
   * Constructor setting the error message.
   *
   * @param message the error message
   */
  public SignServiceProtocolException(final String message) {
    super(message);
  }

  /**
   * Constructor setting the error message and the cause of the error.
   *
   * @param message the error message
   * @param cause the cause of the error
   */
  public SignServiceProtocolException(final String message, final Throwable cause) {
    super(message, cause);
  }

}
