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
package se.swedenconnect.signservice.authn;

import java.util.Objects;

/**
 * Exception class for SignService user authentication exceptions.
 */
public class UserAuthenticationException extends Exception {

  /** For serializing. */
  private static final long serialVersionUID = -9190978864603043003L;

  private final AuthenticationErrorCode errorCode;

  /**
   * Constructor setting the error message.
   *
   * @param errorCode the authentication error code
   * @param message the error message
   */
  public UserAuthenticationException(final AuthenticationErrorCode errorCode, final String message) {
    this(errorCode, message, null);
  }

  /**
   * Constructor setting the error message and the cause of the error.
   *
   * @param errorCode the authentication error code
   * @param message the error message
   * @param cause the cause of the error
   */
  public UserAuthenticationException(final AuthenticationErrorCode errorCode, final String message, final Throwable cause) {
    super(message, cause);
    this.errorCode = Objects.requireNonNull(errorCode, "errorCode must not be null");
  }

  /**
   * Gets the error code.
   * @return the error code
   */
  public AuthenticationErrorCode getErrorCode() {
    return this.errorCode;
  }

}
