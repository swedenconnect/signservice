/*
 * Copyright 2022-2023 Sweden Connect
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

/**
 * Enumeration of authentication error codes.
 */
public enum AuthenticationErrorCode {

  /** The user cancelled the authentication. */
  USER_CANCEL,

  /** The requested authentication service is not known/possible to use. */
  UNKNOWN_AUTHENTICATION_SERVICE,

  /** The authentication did not present the required user identity attributes. */
  MISMATCHING_IDENTITY_ATTRIBUTES,

  /** The requested authentication context is not supported. */
  UNSUPPORTED_AUTHNCONTEXT,

  /** The user failed to authenticate - general authentication error. */
  FAILED_AUTHN,

  /** General error for bad authentication setup. For example, the IdP does not recognize the SP. */
  INTERNAL_AUTHN_ERROR;

}
