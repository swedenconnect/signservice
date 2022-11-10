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
package se.swedenconnect.signservice.certificate;

import java.security.KeyException;
import java.security.cert.CertificateException;

import javax.annotation.Nonnull;

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.SignServiceHandler;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;

/**
 * Defines the handler that is responsible of generating keys and issuing signing certificates.
 */
public interface KeyAndCertificateHandler extends SignServiceHandler {

  /**
   * Verifies that the requirements put in the supplied SignRequest is correct and the handler can process the request.
   * If not a {@link InvalidRequestException} is thrown.
   *
   * @param signRequest the request to check
   * @param context the SignService context
   * @throws InvalidRequestException if the requirements cannot be met
   */
  void checkRequirements(@Nonnull final SignRequestMessage signRequest, @Nonnull final SignServiceContext context)
      throws InvalidRequestException;

  /**
   * Generates a signing (private) key and issues a signing certificate given the supplied parameters.
   *
   * @param signRequest the SignRequest
   * @param assertion the identity assertion (from the user authentication phase)
   * @param context the SignService context
   * @return the generated private key and signing certificate packaged in a {@link PkiCredential}
   * @throws KeyException for key generation errors
   * @throws CertificateException for certificate issuance errors
   */
  @Nonnull
  PkiCredential generateSigningCredential(
      @Nonnull final SignRequestMessage signRequest, @Nonnull final IdentityAssertion assertion,
      @Nonnull final SignServiceContext context) throws KeyException, CertificateException;

}
