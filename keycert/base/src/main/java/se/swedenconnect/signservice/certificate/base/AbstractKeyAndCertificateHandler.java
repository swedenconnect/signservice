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
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.algorithms.Algorithm;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.security.credential.container.PkiCredentialContainerException;
import se.swedenconnect.security.credential.container.keytype.KeyGenType;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMappingData;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMappingException;
import se.swedenconnect.signservice.core.AbstractSignServiceHandler;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.msg.SignatureRequirements;
import se.swedenconnect.signservice.protocol.msg.SigningCertificateRequirements;
import se.swedenconnect.signservice.session.SignServiceContext;

/**
 * Abstract base class for the {@link KeyAndCertificateHandler} interface.
 */
@Slf4j
public abstract class AbstractKeyAndCertificateHandler extends AbstractSignServiceHandler
    implements KeyAndCertificateHandler {

  public static final Map<String, String> DEFAULT_ALGORITHM_KEY_TYPES;

  /** Providers for generating signing key pairs. */
  private final PkiCredentialContainer keyProvider;

  private final Map<String, String> algorithmKeyTypeMap;

  /** Algorithm registry providing information about supported algorithms. */
  private final AlgorithmRegistry algorithmRegistry;

  /** Attribute mapper mapping attribute data from assertion to certificates. */
  private final AttributeMapper attributeMapper;

  /** The type of certificates that the underlying CA issues. */
  private CertificateType caCertificateType = CertificateType.PKC;

  static {
    DEFAULT_ALGORITHM_KEY_TYPES = new HashMap<>();
    DEFAULT_ALGORITHM_KEY_TYPES.put("EC", KeyGenType.EC_P256);
    DEFAULT_ALGORITHM_KEY_TYPES.put("RSA", KeyGenType.RSA_3072);
  }

  /**
   * Service name placed in AuthnContextExtensions. If this value is null, then the service name is set according to
   * local policy which by default should be to use the requesting client ID.
   */
  private String serviceName;

  /**
   * Constructor. The algorithm registry will be set to {@link AlgorithmRegistrySingleton#getInstance()} and the
   * algorithm key types will be NIST P256 for Elliptic curve algorithms and RSA 3072 bit keys for RSA.
   *
   * @param keyProvider a {@link PkiCredentialContainer} acting as the source of generated signing keys
   * @param attributeMapper the attribute mapper
   */
  public AbstractKeyAndCertificateHandler(
      @Nonnull final PkiCredentialContainer keyProvider,
      @Nonnull final AttributeMapper attributeMapper) {
    this(keyProvider, DEFAULT_ALGORITHM_KEY_TYPES, attributeMapper, AlgorithmRegistrySingleton.getInstance());
  }

  /**
   * Constructor.
   *
   * @param keyProvider a {@link PkiCredentialContainer} acting as the source of generated signing keys
   * @param algorithmKeyTypeMap a map of the selected key type for each supported algorithm
   * @param attributeMapper the attribute mapper
   * @param algorithmRegistry algorithm registry
   */
  public AbstractKeyAndCertificateHandler(
      @Nonnull final PkiCredentialContainer keyProvider,
      @Nonnull final Map<String, String> algorithmKeyTypeMap,
      @Nonnull final AttributeMapper attributeMapper,
      @Nonnull final AlgorithmRegistry algorithmRegistry) {
    this.keyProvider = Objects.requireNonNull(keyProvider, "keyProviders must not be null");
    this.algorithmKeyTypeMap = Objects.requireNonNull(algorithmKeyTypeMap, "algorithm key type map must not be null");
    this.attributeMapper = Objects.requireNonNull(attributeMapper, "attributeMapper must not be null");
    this.algorithmRegistry = Objects.requireNonNull(algorithmRegistry, "algorithmRegistry must not be null");

    if (this.algorithmKeyTypeMap.isEmpty()) {
      throw new IllegalArgumentException("At least one key type for one algorithm must be present");
    }
  }

  /** {@inheritDoc} */
  @Override
  public void checkRequirements(@Nonnull final SignRequestMessage signRequest,
      @Nonnull final SignServiceContext context) throws InvalidRequestException {
    log.debug("Checking generic key and certificate issuing requirements on SignRequest");

    // Algorithm tests
    final String signatureAlgorithm = Optional.ofNullable(signRequest.getSignatureRequirements())
        .filter(r -> StringUtils.isNotBlank(r.getSignatureAlgorithm()))
        .map(SignatureRequirements::getSignatureAlgorithm)
        .orElseThrow(() -> new InvalidRequestException("Signature algorithm must be set in sign request"));

    final Algorithm algorithm = this.getAlgorithmRegistry().getAlgorithm(signatureAlgorithm);
    if (algorithm == null) {
      throw new InvalidRequestException("Unsupported signature algorithm: " + signatureAlgorithm);
    }
    if (!(algorithm instanceof SignatureAlgorithm)) {
      throw new InvalidRequestException("Requested signature algorithm is not a valid signature algorithm");
    }
    log.debug("Signature algorithm checks passed for {}", algorithm.getUri());

    final String algorithmType = ((SignatureAlgorithm) algorithm).getKeyType();

    if (!algorithmKeyTypeMap.containsKey(algorithmType)) {
      throw new InvalidRequestException("Unsupported algorithm type: " + algorithmType);
    }
    log.debug("Key type checks passed for {}", algorithmType);

    final SigningCertificateRequirements certificateRequirements = Optional.ofNullable(
        signRequest.getSigningCertificateRequirements())
        .orElseThrow(() -> new InvalidRequestException("Missing certificate requirements"));

    // Check certificate type.
    if (certificateRequirements.getCertificateType() != null) {
      if (!certificateRequirements.getCertificateType().equals(this.getCaCertificateType())) {
        throw new InvalidRequestException("Handler does not support certificate type " +
            certificateRequirements.getCertificateType());
      }
    }

    // Attribute mappings ...
    // TODO: Later we may want to apply a default mapping if none is passed ...
    if (CollectionUtils.isEmpty(certificateRequirements.getAttributeMappings())) {
      throw new InvalidRequestException("Missing attribute mappings in sign request");
    }

    // Check that certificate profile is supported.
    this.assertCertificateProfileSupported(certificateRequirements.getSigningCertificateProfile());
    log.debug("Certificate issuing requirement checks passed");

    // We will not make any specific checks on authentication requirements as they will be tested and accepted by the
    // authentication module.

    log.debug("Checking handler specific key and certificate issuing requirements on SignRequest");
    // Do any other specific compliance tests by the extending class
    this.specificRequirementTests(signRequest, context);
    log.debug("Key and certificate issuing requirements on SignRequest passed");
  }

  /**
   * Implementation specific requirements tests in addition to the basic tests performed by the abstract implementation.
   * The default implementation does nothing.
   *
   * @param signRequest the request to check
   * @param context the SignService context
   * @throws InvalidRequestException if the requirements cannot be met
   */
  protected void specificRequirementTests(@Nonnull final SignRequestMessage signRequest,
      @Nonnull final SignServiceContext context) throws InvalidRequestException {
  }

  /** {@inheritDoc} */
  @Override
  public PkiCredential generateSigningCredential(@Nonnull final SignRequestMessage signRequest,
      @Nonnull final IdentityAssertion assertion, @Nonnull final SignServiceContext context)
    throws CertificateException, KeyException {

    // Map attributes from the assertion to certificate attributes ...
    //
    List<AttributeMappingData> certAttributes = null;
    try {
      log.debug("Get mapping data from configured attribute mapper");
      certAttributes = this.getAttributeMapper().mapCertificateAttributes(signRequest, assertion);
    }
    catch (final AttributeMappingException e) {
      log.debug("Attribute mapping failed: {}", e.toString());
      throw new CertificateException("Attribute mapping failed", e);
    }

    // Get signature algorithm
    final SignatureAlgorithm algorithm = (SignatureAlgorithm) this.getAlgorithmRegistry().getAlgorithm(
        Optional.ofNullable(signRequest.getSignatureRequirements())
            .map(SignatureRequirements::getSignatureAlgorithm)
            .orElseThrow(() -> new IllegalArgumentException("Signature algorithm must not be null")));

    // Obtain the raw key pair (public and private key)
    //
    final PkiCredential signingKeyCredentials;
    try {
      String keyType = algorithmKeyTypeMap.get(algorithm.getKeyType());
      String alias = this.keyProvider.generateCredential(keyType);

      signingKeyCredentials = this.keyProvider.getCredential(alias);
    }
    catch (NoSuchAlgorithmException e) {
      throw new KeyException("Algorithm not supported", e);
    }
    catch (PkiCredentialContainerException e) {
      throw new KeyException("PkiCredentialContainer error", e);
    }
    log.debug("Issued key pair for key type {}", algorithm.getKeyType());

    // Get the signer certificate for the public key
    //
    final String certificateProfile = Optional.ofNullable(signRequest.getSigningCertificateRequirements())
        .map(SigningCertificateRequirements::getSigningCertificateProfile)
        .orElse(null);

    final List<X509Certificate> signerCertificateChain =
        this.issueSigningCertificateChain(signingKeyCredentials, signRequest, assertion, certAttributes,
            certificateProfile, context);

    // Add signer certificate chain to key credentials
    signingKeyCredentials.setCertificateChain(signerCertificateChain);

    return signingKeyCredentials;
  }

  /**
   * Issues the signing certificate for the signing credentials. Note that the context parameter holds information about
   * algorithm, cert type and profile where default values as been taken into account. The signRequest only holds the
   * values from the actual request.
   *
   * @param signingKeyPair signing key pair
   * @param signRequest sign request
   * @param assertion assertion providing asserted user identity
   * @param certAttributes the certificate attributes to include in the certificate
   * @param certificateProfile the certificate profile (may be null)
   * @param context signature context providing additional information
   * @return the certificate chain where the signer certificate is placed first
   * @throws CertificateException error obtaining a certificate for the signer
   */
  protected abstract List<X509Certificate> issueSigningCertificateChain(@Nonnull final PkiCredential signingKeyPair,
      @Nonnull final SignRequestMessage signRequest, @Nonnull final IdentityAssertion assertion,
      @Nonnull final List<AttributeMappingData> certAttributes, @Nullable final String certificateProfile,
      @Nonnull final SignServiceContext context) throws CertificateException;

  /**
   * Test if the requested certificate profile is supported.
   *
   * @param certificateProfile the profile requested for the certificate or null
   * @throws InvalidRequestException if the requested certificate profile is not supported
   */
  protected abstract void assertCertificateProfileSupported(@Nullable final String certificateProfile)
      throws InvalidRequestException;

  /**
   * Gets the service name placed in AuthnContextExtensions. If this value is null, then the service name is set
   * according to local policy which by default should be to use the requesting client ID.
   *
   * @return the service name or null
   */
  @Nullable
  protected String getServiceName() {
    return this.serviceName;
  }

  /**
   * Assigns the service name placed in AuthnContextExtensions. If this value is null, then the service name is set
   * according to local policy which by default should be to use the requesting client ID.
   *
   * @param serviceName service name for inclusion in AuthnContextExtensions
   */
  public void setServiceName(@Nullable final String serviceName) {
    this.serviceName = serviceName;
  }

  /**
   * Gets the type of certificates that the underlying CA issues.
   *
   * @return the certificate type
   */
  @Nonnull
  protected CertificateType getCaCertificateType() {
    return this.caCertificateType;
  }

  /**
   * Assigns the type of certificates that the underlying CA issues.
   *
   * @param certificateType the certificate type
   */
  public void setCaCertificateType(@Nonnull final CertificateType certificateType) {
    if (certificateType != null) {
      this.caCertificateType = certificateType;
    }
  }

  /**
   * Gets the algorithm registry providing information about supported algorithms.
   *
   * @return the algorithm registry
   */
  protected AlgorithmRegistry getAlgorithmRegistry() {
    return this.algorithmRegistry;
  }

  /**
   * Gets the attribute mapper.
   *
   * @return the attribute mapper
   */
  protected AttributeMapper getAttributeMapper() {
    return this.attributeMapper;
  }

}
