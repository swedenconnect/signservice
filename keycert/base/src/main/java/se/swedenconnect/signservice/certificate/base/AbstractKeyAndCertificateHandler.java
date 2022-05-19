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

import lombok.NonNull;
import se.swedenconnect.security.algorithms.Algorithm;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.configuration.DefaultConfiguration;
import se.swedenconnect.signservice.certificate.base.configuration.DefaultParameter;
import se.swedenconnect.signservice.certificate.base.keyprovider.SignServiceSigningKeyProvider;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.msg.SignatureRequirements;
import se.swedenconnect.signservice.protocol.msg.SigningCertificateRequirements;
import se.swedenconnect.signservice.session.SignServiceContext;

import java.security.KeyException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

/**
 * Abstract base class for the {@link KeyAndCertificateHandler} interface.
 */
public abstract class AbstractKeyAndCertificateHandler implements KeyAndCertificateHandler {

  /** Provider of generated signing key pairs */
  protected final SignServiceSigningKeyProvider signingKeyProvider;
  /** Source of default configuration parameters relevant for key generation and certificate generation */
  protected final DefaultConfiguration defaultConfiguration;
  /** Algorithm registry providing information about supported algorithms */
  protected final AlgorithmRegistry algorithmRegistry;

  /**
   * Constructor for the key and certificate handler
   *
   * @param signingKeyProvider provider for providing signing keys
   */
  public AbstractKeyAndCertificateHandler(final @NonNull SignServiceSigningKeyProvider signingKeyProvider,
    final @NonNull DefaultConfiguration defaultConfiguration, final @NonNull AlgorithmRegistry algorithmRegistry) {
    this.signingKeyProvider = signingKeyProvider;
    this.defaultConfiguration = defaultConfiguration;
    this.algorithmRegistry = algorithmRegistry;
  }

  /** {@inheritDoc} */
  @Override
  public void checkRequirements(final SignRequestMessage signRequest, final SignServiceContext context)
    throws InvalidRequestException {

    String clientId = Optional.ofNullable(signRequest.getClientId())
      .orElseThrow(() -> new InvalidRequestException("Null client ID"));

    // Algorithm tests
    SignatureRequirements signatureRequirements = Optional.ofNullable(signRequest.getSignatureRequirements())
      .orElseThrow(() -> new InvalidRequestException("Null signature requirements"));
    String signatureAlgorithm = Optional.ofNullable(signatureRequirements.getSignatureAlgorithm())
      .orElse(defaultConfiguration.get(DefaultParameter.signatureAlgorithm.getParameterName(), clientId, String.class));
    if (signatureAlgorithm == null) {
      throw new InvalidRequestException("No signature algorithm in request or in default parameters");
    }

    Algorithm algorithm = algorithmRegistry.getAlgorithm(signatureAlgorithm);
    if (!(algorithm instanceof SignatureAlgorithm)) {
      throw new InvalidRequestException("Defined signature algorithm is not a signature algorithm");
    }

    List<String> supportedKeyTypeList = signingKeyProvider.getSupportedKeyTypes();
    if (!supportedKeyTypeList.contains(((SignatureAlgorithm) algorithm).getKeyType())) {
      throw new InvalidRequestException("Unsupported key type " + ((SignatureAlgorithm) algorithm).getKeyType());
    }

    SigningCertificateRequirements certificateRequirements = Optional.ofNullable(
        signRequest.getSigningCertificateRequirements())
      .orElseThrow(() -> new InvalidRequestException("Null certificate requirements"));

    CertificateType certificateType = Optional.ofNullable(certificateRequirements.getCertificateType())
      .orElse(
        defaultConfiguration.get(DefaultParameter.certificateType.getParameterName(), clientId, CertificateType.class));
    if (certificateType == null) {
      throw new InvalidRequestException("No certificate type in request or in default parameters");
    }
    String signingCertificateProfile = Optional.ofNullable(certificateRequirements.getSigningCertificateProfile())
      .orElse(defaultConfiguration.get(DefaultParameter.certificateProfile.getParameterName(), clientId, String.class));

    // Check that certificate type and profile is supported
    isCertificateTypeSupported(certificateType, signingCertificateProfile);

    // We will not make any specific checks on authentication requirements as they will be tested and accepted by the
    // authentication module.

    // Do any other specific compliance tests by the extending class
    specificRequirementTests(signRequest, context);
  }

  /**
   * Implementation specific requirements tests in addition to the basic tests performed by the abstract implementation
   *
   * @param signRequest the request to check
   * @param context the SignService context
   * @throws InvalidRequestException if the requirements cannot be met
   */
  protected abstract void specificRequirementTests(final SignRequestMessage signRequest,
    final SignServiceContext context) throws InvalidRequestException;

  /** {@inheritDoc} */
  @Override
  public PkiCredential generateSigningCredential(final SignRequestMessage signRequest,
    final IdentityAssertion assertion, final SignServiceContext context) throws KeyException, CertificateException {

    String clientId = signRequest.getClientId();
    // Get signature and cert requirements. We throw NullPointer Exception here because this is an unrecoverable error
    // that should be impossible given that we have made a compliance check before as requested by the engine.
    SignatureRequirements signatureRequirements = Optional.ofNullable(signRequest.getSignatureRequirements())
      .orElseThrow(() -> new NullPointerException("No signature requirements provided"));
    SigningCertificateRequirements certificateRequirements = Optional.ofNullable(
        signRequest.getSigningCertificateRequirements())
      .orElseThrow(() -> new NullPointerException("No certificate requirements provided"));

    // We extract and store the actual values of algorithm, cert type and profile as the sign request doesn't
    // contain default config values. The cert module should obtain the actual values from the context stored here.

    // Determine and store signature algorithm
    String signatureAlgorithm = Optional.ofNullable(signatureRequirements.getSignatureAlgorithm())
      .orElse(defaultConfiguration.get(DefaultParameter.signatureAlgorithm.getParameterName(), clientId, String.class));
    context.put(DefaultParameter.signatureAlgorithm.getParameterName(), signatureAlgorithm);

    // Determine and store certificate type
    CertificateType certificateType = Optional.ofNullable(certificateRequirements.getCertificateType())
      .orElse(
        defaultConfiguration.get(DefaultParameter.certificateType.getParameterName(), clientId, CertificateType.class));
    context.put(DefaultParameter.certificateType.getParameterName(), certificateType);

    // Determine and store certificate profile
    String certificateProfile = Optional.ofNullable(certificateRequirements.getSigningCertificateProfile())
      .orElse(defaultConfiguration.get(DefaultParameter.certificateProfile.getParameterName(), clientId, String.class));
    context.put(DefaultParameter.certificateProfile.getParameterName(), certificateProfile);

    SignatureAlgorithm algorithm = (SignatureAlgorithm) algorithmRegistry.getAlgorithm(signatureAlgorithm);
    KeyPair signingKeyPair = signingKeyProvider.getSigningKeyPair(algorithm.getKeyType(), context);
    X509Certificate signerCertificate = obtainSigningCertificate(signingKeyPair, signRequest, assertion, context);
    return new BasicCredential(signerCertificate, signingKeyPair.getPrivate());
  }

  /**
   * Obtaining the signing certificate for the signing credentials. Note that the context parameter
   * holds information about algorithm, cert type and profile where default values as been taken into
   * account. The signRequest only holds the values from the actual request.
   *
   * @param signingKeyPair signing key pair
   * @param signRequest sign request
   * @param assertion assertion providing asserted user identity
   * @param context signature context providing additional information
   * @return the certificate of the signer
   * @throws CertificateException error obtaining a certificate for the signer
   */
  protected abstract X509Certificate obtainSigningCertificate(@NonNull final KeyPair signingKeyPair,
    @NonNull final SignRequestMessage signRequest, @NonNull final IdentityAssertion assertion,
    final SignServiceContext context) throws CertificateException;

  /**
   * Test if the requested certificate type is supported
   *
   * @param certificateType the certificate type (PKC , QC or QC with SSCD)
   * @param certificateProfile the profile requested for the certificate or null
   * @throws InvalidRequestException if the requested certificate type is not supported
   */
  protected abstract void isCertificateTypeSupported(@NonNull final CertificateType certificateType,
    final String certificateProfile) throws InvalidRequestException;
}


