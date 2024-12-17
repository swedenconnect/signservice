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
package se.swedenconnect.signservice.engine;

import java.util.Optional;

/**
 * Exception class for reporting a {@link SignServiceError}.
 */
public class SignServiceErrorException extends Exception {

  /** For serializing. */
  private static final long serialVersionUID = 300880177166442286L;

  /** The error. */
  private final SignServiceError error;

  /**
   * Constructor setting the error.
   *
   * @param error the error
   */
  public SignServiceErrorException(final SignServiceError error) {
    super(Optional.ofNullable(error).map(SignServiceError::getMessage).orElse(null));
    this.error = error;
  }

  /**
   * Constructor setting the error and the cause of the exception.
   *
   * @param error the error
   * @param cause the cause
   */
  public SignServiceErrorException(final SignServiceError error, final Throwable cause) {
    super(Optional.ofNullable(error).map(SignServiceError::getMessage).orElse(null), cause);
    this.error = error;
  }

  /**
   * Gets the {@link SignServiceError}.
   *
   * @return the error
   */
  public SignServiceError getError() {
    return this.error;
  }

}
