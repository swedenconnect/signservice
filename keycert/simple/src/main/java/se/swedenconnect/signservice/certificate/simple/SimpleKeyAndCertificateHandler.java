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
package se.swedenconnect.signservice.certificate.simple;

import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.certificate.base.AbstractKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.keyprovider.SignServiceSigningKeyProvider;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.session.SignServiceContext;

import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * A simple key and certificate handler.
 */
public class SimpleKeyAndCertificateHandler extends AbstractKeyAndCertificateHandler {

  /**
   * Constructor for the key and certificate handler
   *
   * @param signingKeyProvider provider for providing signing keys
   */
  public SimpleKeyAndCertificateHandler(
    SignServiceSigningKeyProvider signingKeyProvider, AlgorithmRegistry algorithmRegistry) {
    super(signingKeyProvider, algorithmRegistry);
  }

  /**
   * Obtaining the signing certificate for the signing credentials
   *
   * @param signingKeyPair signing key pair
   * @param signRequest sign request
   * @param assertion assertion providing asserted user identity
   * @param context signature context providing additional information
   * @return certificate public key of the signer
   * @throws CertificateException error obtaining a certificate for the signer
   */
  @Override protected X509Certificate obtainSigningCertificate(KeyPair signingKeyPair, SignRequestMessage signRequest,
    IdentityAssertion assertion, SignServiceContext context) throws CertificateException {
    return null;
  }

}
