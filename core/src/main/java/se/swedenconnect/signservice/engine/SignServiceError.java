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

import java.util.Optional;

/**
 * A generic representation of a SignService error. The class wraps a {@link SignServiceErrorCode} and offers the
 * possibility to add a error message (overriding the default message from {@link SignServiceErrorCode}) and also a
 * detailed error message.
 */
public class SignServiceError {

  /** The error code. */
  private final SignServiceErrorCode errorCode;

  /** The error message. */
  private final String message;

  /** A detailed error message. */
  private final String detailedMessage;

  /**
   * Constructor.
   *
   * @param errorCode the error code
   */
  public SignServiceError(final SignServiceErrorCode errorCode) {
    this(errorCode, null, null);
  }

  /**
   * Constructor.
   *
   * @param errorCode the error code
   * @param message the message to use (overriding the default message from errorCode)
   */
  public SignServiceError(final SignServiceErrorCode errorCode, final String message) {
    this(errorCode, message, null);
  }

  /**
   * Constructor.
   *
   * @param errorCode the error code
   * @param message the message to use (overriding the default message from errorCode)
   * @param detailedMessage a detailed message
   */
  public SignServiceError(final SignServiceErrorCode errorCode, final String message, final String detailedMessage) {
    this.errorCode = errorCode;
    this.message = message;
    this.detailedMessage = detailedMessage;
  }

  /**
   * Gets the error code.
   * @return the error code
   */
  public SignServiceErrorCode getErrorCode() {
    return this.errorCode;
  }

  /**
   * Gets the error message.
   *
   * @return the error message
   */
  public String getMessage() {
    return Optional.ofNullable(this.message).orElse(this.errorCode.getDefaultMessage());
  }

  /**
   * Gets the detailed error message.
   *
   * @return the detailed error message, or null if not set
   */
  public String getDetailedMessage() {
    return this.detailedMessage;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("error-code='%s', message='%s', detailed-message='%s'",
        this.errorCode, this.getMessage(), this.detailedMessage);
  }

}
