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
package se.swedenconnect.signservice.api.engine;

/**
 * Symbols for "unrecoverable error codes". These kinds of errors are reported back to the application when the engine
 * has no way of constructing an ordinary error response message.
 *
 * @see UnrecoverableSignServiceException
 */
public class UnrecoverableErrorCodes {

  /** Prefix for "unrecoverable" error codes. */
  private static final String ERROR_PREFIX = "error.unrecoverable.";

  /** The client is not not known to the SignService (i.e., is not registered). */
  public static final String UNKNOWN_CLIENT = ERROR_PREFIX + "unknown-client";

  /**
   * A request received from the client could not be validated, i.e., its signature failed to verify.
   */
  public static final String AUTHN_FAILED = ERROR_PREFIX + "authn-failed";

  /** A request received could not be successfully decoded. */
  public static final String PROTOCOL_ERROR = ERROR_PREFIX + "protocol-error";

  // TODO: Define more error codes

  /** Represents an internal SignService error. */
  public static final String INTERNAL_ERROR = ERROR_PREFIX + "internal-error";

  // Hidden constructor.
  private UnrecoverableErrorCodes() {
  }

}
