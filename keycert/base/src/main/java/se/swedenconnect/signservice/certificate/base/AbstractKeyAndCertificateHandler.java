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
package se.swedenconnect.signservice.certificate.base;

import java.security.KeyException;
import java.security.cert.CertificateException;

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.session.SignServiceContext;

/**
 * Abstract base class for the {@link KeyAndCertificateHandler} interface.
 */
public abstract class AbstractKeyAndCertificateHandler implements KeyAndCertificateHandler {

  private final SignServiceSigningKeyProvider signingKeyProvider;

  /**
   * Constructor for the key and certificate handler
   * @param signingKeyProvider provider for providing signing keys
   */
  public AbstractKeyAndCertificateHandler(
    SignServiceSigningKeyProvider signingKeyProvider) {
    this.signingKeyProvider = signingKeyProvider;
  }

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public void checkRequirements(final SignRequestMessage signRequest, final SignServiceContext context)
      throws InvalidRequestException {

    

  }

  /** {@inheritDoc} */
  @Override
  public PkiCredential generateSigningCredential(final SignRequestMessage signRequest,
      final IdentityAssertion assertion, final SignServiceContext context) throws KeyException, CertificateException {

    return null;
  }

}
