/*
 * Copyright 2022-2025 Sweden Connect
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

/**
 * Generic SignService error codes. These are the internal representation of errors that may be reported back from the
 * SignService to the client. These and only these.
 */
public enum SignServiceErrorCode {

  /** The received request is incorrect. */
  REQUEST_INCORRECT("The sign request message is incorrect"),

  /** The request has expired, i.e., does not meet the constraints for how old it is allowed to be. */
  REQUEST_EXPIRED("The sign request message has expired"),

  /** User cancelled authentication. */
  AUTHN_USER_CANCEL("User cancelled authentication"),

  /** The user information received after authentication does not match requested user identity. */
  AUTHN_USER_MISMATCH("User identity does not match requested identity attributes"),

  /** The requested authentication context is not supported by the requested authentication service. */
  AUTHN_UNSUPPORTED_AUTHNCONTEXT("The requested authentication context is not supported"),

  /**
   * A requirement to display sign message was included in the sign request, but the sign service could not establish
   * that the sign message was displayed to the user.
   */
  AUTHN_SIGNMESSAGE_NOT_DISPLAYED("Sign message was not displayed to the user which was required"),

  /** General authentication error. */
  AUTHN_FAILURE("The user failed to authenticate"),

  /** Security violation. */
  SECURITY_VIOLATION("A security violation was detected"),

  /** Error generating the signing key. */
  KEY_GENERATION_FAILED("The generation of the signature key failed"),

  /** Failed to issue signing certificate. */
  CERT_ISSUANCE_FAILED("The issuance of a signing certificate failed"),

  /** The catch-all case. Returned, if no other error is suitable. */
  INTERNAL_ERROR("An internal error occurred in the SignService");

  /**
   * Gets the default message for the error code.
   *
   * @return the default error message
   */
  public String getDefaultMessage() {
    return this.defaultMessage;
  }

  /** The default message for this error code. */
  private String defaultMessage;

  /**
   * Constructor.
   *
   * @param defaultMessage default message for this error code
   */
  private SignServiceErrorCode(final String defaultMessage) {
    this.defaultMessage = defaultMessage;
  }

}
