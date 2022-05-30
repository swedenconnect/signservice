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
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

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
   * Constructor for the key and certificate handler.
   *
   * @param signingKeyProvider provider for providing signing keys
   * @param defaultConfiguration default value configuration data
   * @param algorithmRegistry algorithm registry
   */
  public AbstractKeyAndCertificateHandler(@Nonnull final SignServiceSigningKeyProvider signingKeyProvider,
      @Nonnull final DefaultConfiguration defaultConfiguration, @Nonnull final AlgorithmRegistry algorithmRegistry) {
    this.signingKeyProvider = Objects.requireNonNull(signingKeyProvider, "signingKeyProvider must not be null");
    this.defaultConfiguration = Objects.requireNonNull(defaultConfiguration, "defaultConfiguration must not be null");
    this.algorithmRegistry = Objects.requireNonNull(algorithmRegistry, "algorithmRegistry must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public void checkRequirements(@Nonnull final SignRequestMessage signRequest,
      @Nonnull final SignServiceContext context)
      throws InvalidRequestException {

    final String clientId = Optional.ofNullable(signRequest.getClientId())
        .orElseThrow(() -> new InvalidRequestException("No client ID available"));

    // Algorithm tests
    final String signatureAlgorithm = Optional.ofNullable(signRequest.getSignatureRequirements())
        .map(SignatureRequirements::getSignatureAlgorithm)
        .orElseGet(
            () -> this.defaultConfiguration.get(
                DefaultParameter.signatureAlgorithm.getParameterName(), clientId, String.class));
    if (signatureAlgorithm == null) {
      throw new InvalidRequestException("No signature algorithm in request or in default parameters");
    }

    final Algorithm algorithm = this.algorithmRegistry.getAlgorithm(signatureAlgorithm);
    if (!(algorithm instanceof SignatureAlgorithm)) {
      throw new InvalidRequestException("Defined signature algorithm is not a signature algorithm");
    }

    final List<String> supportedKeyTypeList = this.signingKeyProvider.getSupportedKeyTypes();
    if (!supportedKeyTypeList.contains(((SignatureAlgorithm) algorithm).getKeyType())) {
      throw new InvalidRequestException("Unsupported key type " + ((SignatureAlgorithm) algorithm).getKeyType());
    }

    final SigningCertificateRequirements certificateRequirements = Optional.ofNullable(
        signRequest.getSigningCertificateRequirements())
        .orElseThrow(() -> new InvalidRequestException("Missing certificate requirements"));

    final CertificateType certificateType = Optional.ofNullable(certificateRequirements.getCertificateType())
        .orElse(
            this.defaultConfiguration.get(DefaultParameter.certificateType.getParameterName(), clientId,
                CertificateType.class));
    if (certificateType == null) {
      throw new InvalidRequestException("No certificate type in request or in default parameters");
    }
    final String signingCertificateProfile = Optional.ofNullable(certificateRequirements.getSigningCertificateProfile())
        .orElse(
            this.defaultConfiguration.get(DefaultParameter.certificateProfile.getParameterName(), clientId,
                String.class));

    // Check that certificate type and profile is supported
    this.isCertificateTypeSupported(certificateType, signingCertificateProfile);

    // We will not make any specific checks on authentication requirements as they will be tested and accepted by the
    // authentication module.

    // Do any other specific compliance tests by the extending class
    this.specificRequirementTests(signRequest, context);
  }

  /**
   * Implementation specific requirements tests in addition to the basic tests performed by the abstract implementation.
   *
   * @param signRequest the request to check
   * @param context the SignService context
   * @throws InvalidRequestException if the requirements cannot be met
   */
  protected abstract void specificRequirementTests(@Nonnull final SignRequestMessage signRequest,
      @Nonnull final SignServiceContext context) throws InvalidRequestException;

  /** {@inheritDoc} */
  @Override
  public PkiCredential generateSigningCredential(final SignRequestMessage signRequest,
      final IdentityAssertion assertion, final SignServiceContext context) throws KeyException, CertificateException {

    final String clientId = signRequest.getClientId();

    // Get cert requirements. We throw NullPointer Exception here because this is an unrecoverable error
    // that should be impossible given that we have made a compliance check before as requested by the engine.

    final SigningCertificateRequirements certificateRequirements = Optional.ofNullable(
        signRequest.getSigningCertificateRequirements())
        .orElseThrow(() -> new NullPointerException("No certificate requirements provided"));

    // We extract and store the actual values of algorithm, cert type and profile as the sign request doesn't
    // contain default config values. The cert module should obtain the actual values from the context stored here.

    // Determine and store signature algorithm
    final String signatureAlgorithm = Optional.ofNullable(signRequest.getSignatureRequirements())
        .map(SignatureRequirements::getSignatureAlgorithm)
        .orElseGet(() -> { return Optional.ofNullable(this.defaultConfiguration.get(
              DefaultParameter.signatureAlgorithm.getParameterName(), clientId, String.class))
              .orElseThrow(
                  () -> new IllegalArgumentException("No signature algorithm in request or in default parameters"));
        });

    context.put(DefaultParameter.signatureAlgorithm.getParameterName(), signatureAlgorithm);

    // Determine and store certificate type
    final CertificateType certificateType = Optional.ofNullable(certificateRequirements.getCertificateType())
        .orElse(
            this.defaultConfiguration.get(DefaultParameter.certificateType.getParameterName(), clientId,
                CertificateType.class));
    context.put(DefaultParameter.certificateType.getParameterName(), certificateType);

    // Determine and store certificate profile
    final String certificateProfile = Optional.ofNullable(certificateRequirements.getSigningCertificateProfile())
        .orElse(
            this.defaultConfiguration.get(DefaultParameter.certificateProfile.getParameterName(), clientId,
                String.class));
    context.put(DefaultParameter.certificateProfile.getParameterName(), certificateProfile);

    final SignatureAlgorithm algorithm = (SignatureAlgorithm) this.algorithmRegistry.getAlgorithm(signatureAlgorithm);
    final KeyPair signingKeyPair = this.signingKeyProvider.getSigningKeyPair(algorithm.getKeyType(), context);
    final X509Certificate signerCertificate =
        this.obtainSigningCertificate(signingKeyPair, signRequest, assertion, context);

    return new BasicCredential(signerCertificate, signingKeyPair.getPrivate());
  }

  /**
   * Obtaining the signing certificate for the signing credentials. Note that the context parameter holds information
   * about algorithm, cert type and profile where default values as been taken into account. The signRequest only holds
   * the values from the actual request.
   *
   * @param signingKeyPair signing key pair
   * @param signRequest sign request
   * @param assertion assertion providing asserted user identity
   * @param context signature context providing additional information
   * @return the certificate of the signer
   * @throws CertificateException error obtaining a certificate for the signer
   */
  protected abstract X509Certificate obtainSigningCertificate(@Nonnull final KeyPair signingKeyPair,
      @Nonnull final SignRequestMessage signRequest, @Nonnull final IdentityAssertion assertion,
      @Nonnull final SignServiceContext context) throws CertificateException;

  /**
   * Test if the requested certificate type is supported.
   *
   * @param certificateType the certificate type (PKC , QC or QC with SSCD)
   * @param certificateProfile the profile requested for the certificate or null
   * @throws InvalidRequestException if the requested certificate type is not supported
   */
  protected abstract void isCertificateTypeSupported(@Nonnull final CertificateType certificateType,
      @Nullable final String certificateProfile) throws InvalidRequestException;
}
