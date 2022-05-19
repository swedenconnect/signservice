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

import lombok.NonNull;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.certificate.base.AbstractKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.configuration.DefaultConfiguration;
import se.swedenconnect.signservice.certificate.base.keyprovider.SignServiceSigningKeyProvider;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
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
   * @param defaultConfiguration
   * @param algorithmRegistry
   */
  public SimpleKeyAndCertificateHandler(
    @NonNull SignServiceSigningKeyProvider signingKeyProvider,
    @NonNull DefaultConfiguration defaultConfiguration,
    @NonNull AlgorithmRegistry algorithmRegistry) {
    super(signingKeyProvider, defaultConfiguration, algorithmRegistry);
  }

  /**
   * Gets the name of the handler.
   *
   * @return the handler name
   */
  @Override public String getName() {
    return "simple-key-cert-handler";
  }

  /**
   * Implementation specific requirements tests in addition to the basic tests performed by the abstract implementation
   *
   * @param signRequest the request to check
   * @param context the SignService context
   * @throws InvalidRequestException if the requirements cannot be met
   */
  @Override protected void specificRequirementTests(SignRequestMessage signRequest,
    SignServiceContext context) throws InvalidRequestException {

  }

  /**
   * Obtaining the signing certificate for the signing credentials
   *
   * @param signingKeyPair signing key pair
   * @param signRequest sign request
   * @param assertion assertion providing asserted user identity
   * @param context signature context providing additional information
   * @return the certificate of the signer
   * @throws CertificateException error obtaining a certificate for the signer
   */
  @Override protected X509Certificate obtainSigningCertificate(@NonNull KeyPair signingKeyPair,
    @NonNull SignRequestMessage signRequest, @NonNull IdentityAssertion assertion,
    SignServiceContext context) throws CertificateException {
    return null;
  }

  /**
   * Test if the requested certificate type is supported
   *
   * @param certificateType the certificate type (PKC , QC or QC with SSCD)
   * @param certificateProfile the profile requested for the certificate or null
   * @throws InvalidRequestException if the requested certificate type is not supported
   */
  @Override protected void isCertificateTypeSupported(@NonNull CertificateType certificateType,
    String certificateProfile) throws InvalidRequestException {

  }
}
