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
package se.swedenconnect.signservice.engine;

import java.util.Objects;

/**
 * Exception class for representing "unrecoverable" errors. Such an error can occur when the engine detects that it can
 * not send an ordinary error response message back to the client. Typically this happens when a request is received
 * where the engine can not authenticate the invoking client.
 *
 * @see UnrecoverableErrorCodes
 */
public class UnrecoverableSignServiceException extends Exception {

  /** For serializing. */
  private static final long serialVersionUID = 4075792107782598756L;

  /** The error code. */
  private final String errorCode;

  /**
   * Constructor setting the error code and an error message.
   *
   * @param errorCode the error code
   * @param message the error message
   */
  public UnrecoverableSignServiceException(final String errorCode, final String message) {
    this(errorCode, message, null);
  }

  /**
   * Constructor setting the error code, an error message and the cause of the error.
   *
   * @param errorCode the error code
   * @param message the error message
   * @param cause the cause of the error
   */
  public UnrecoverableSignServiceException(final String errorCode, final String message, final Throwable cause) {
    super(message, cause);
    this.errorCode = Objects.requireNonNull(errorCode, "errorCode must not be null");
  }

  /**
   * Gets the error code.
   *
   * @return the error code
   */
  public String getErrorCode() {
    return this.errorCode;
  }

}
