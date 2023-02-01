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
package se.swedenconnect.signservice.certificate.cmc;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.commons.lang.StringUtils;
import org.apache.xml.security.signature.XMLSignature;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.certificate.CertificateUtils;
import se.swedenconnect.ca.cmc.CMCException;
import se.swedenconnect.ca.cmc.api.client.CMCClient;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.AbstractCertificateModelBuilder;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.base.AbstractCaEngineKeyAndCertificateHandler;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.types.InvalidRequestException;

/**
 * CMC based key and certificate handler obtaining certificates from a remote CA using CMC.
 */
@Slf4j
public class CMCKeyAndCertificateHandler extends AbstractCaEngineKeyAndCertificateHandler {

  /** CMC Client for remote CA service used to issue certificates. */
  private final CMCClient cmcClient;

  /** The CA chain. */
  private final List<X509Certificate> caChain;

  /** The certificate request format. */
  private final CertificateRequestFormat certificateRequestFormat;

  /**
   * Constructor.
   *
   * @param keyProvider a {@link PkiCredentialContainer} acting as the source of generated signing keys
   * @param algorithmKeyTypes a map of the selected key type for each supported algorithm
   * @param attributeMapper the attribute mapper
   * @param algorithmRegistry algorithm registry
   * @param cmcClient CMC client used to issue certificates using CMC
   * @param certificateRequestFormat the certificate request format (defaults to
   *          {@link CertificateRequestFormat#pkcs10}).
   */
  public CMCKeyAndCertificateHandler(
      @Nonnull final PkiCredentialContainer keyProvider,
      @Nullable final Map<String, String> algorithmKeyTypes,
      @Nonnull final AttributeMapper attributeMapper,
      @Nullable final AlgorithmRegistry algorithmRegistry,
      @Nonnull final CMCClient cmcClient,
      @Nullable final CertificateRequestFormat certificateRequestFormat) {
    super(keyProvider, algorithmKeyTypes, attributeMapper, algorithmRegistry);
    this.cmcClient = Objects.requireNonNull(cmcClient, "cmcClient must not be null");
    this.certificateRequestFormat = Optional.ofNullable(certificateRequestFormat)
        .orElse(CertificateRequestFormat.pkcs10);
    this.caChain = new ArrayList<>();
    try {
      for (final byte[] encoding : cmcClient.getStaticCAInformation().getCertificateChain()) {
        this.caChain.add(CertificateUtils.decodeCertificate(encoding));
      }
    }
    catch (final Exception e) {
      throw new SecurityException("Failed to get CA certificate chain", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected List<X509Certificate> issueSigningCertificateChain(
      @Nonnull final CertificateModel certificateModel, @Nullable final PkiCredential signerCredential,
      @Nullable final String certificateProfile, @Nonnull final SignServiceContext context)
      throws CertificateException {

    try {
      String pkcs10SigningAlgorithm = null;
      PrivateKey requestFormatSigningKey = null;
      final byte[] regInfo =
          StringUtils.isNotBlank(certificateProfile) ? certificateProfile.getBytes(StandardCharsets.UTF_8) : null;
      if (this.certificateRequestFormat.equals(CertificateRequestFormat.pkcs10)) {
        if (signerCredential == null) {
          throw new IllegalArgumentException("signerCredential is required for PKCS#10 request format");
        }
        pkcs10SigningAlgorithm = this.getCertRequestFormatSigningAlgorithm(signerCredential.getPublicKey());
        requestFormatSigningKey = signerCredential.getPrivateKey();
      }
      final CMCResponse cmcResponse = this.cmcClient.issueCertificate(certificateModel, requestFormatSigningKey,
          pkcs10SigningAlgorithm, regInfo);
      final CMCResponseStatus responseStatus = cmcResponse.getResponseStatus();
      if (!responseStatus.getStatus().equals(CMCStatusType.success)) {
        final CMCFailType failType = responseStatus.getFailType();
        final String failTypeMessage =
            responseStatus.getMessage() != null ? ", Message: " + responseStatus.getMessage() : "";
        final String message = String.format("Status: %s, Failure type: %s %s",
            responseStatus.getStatus().name(), failType.name(), failTypeMessage);
        log.debug("Failed to issue requested certificate: {}", message);
        throw new CertificateException(message);
      }
      final List<X509Certificate> chain = new ArrayList<>();
      chain.add(cmcResponse.getReturnCertificates().get(0));
      chain.addAll(this.caChain);
      return chain;
    }
    catch (final CMCException e) {
      final String msg = "Failed to complete CMC request - " + e.getMessage();
      log.info("{}", msg, e);
      throw new CertificateException(msg, e);
    }
  }

  private String getCertRequestFormatSigningAlgorithm(final PublicKey publicKey) throws CertificateException {
    if (publicKey instanceof ECPublicKey) {
      return XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256;
    }
    if (publicKey instanceof RSAPublicKey) {
      return XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256;
    }
    throw new CertificateException("Unsupported key type for generating PKCS10 requests");
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected AbstractCertificateModelBuilder<? extends AbstractCertificateModelBuilder<?>> createCertificateModelBuilder(
      @Nonnull final PublicKey subjectPublicKey, @Nonnull final CertNameModel<?> subject) throws CertificateException {
    try {
      // TODO: Make configurable (OCSP and CRL DP)
      return this.cmcClient.getCertificateModelBuilder(subjectPublicKey, subject, true, true);
    }
    catch (final CMCException e) {
      throw new CertificateException("Error obtaining certificate model from CMC client", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  protected void assertCertificateProfileSupported(
      @Nullable final String certificateProfile) throws InvalidRequestException {
    if (StringUtils.isNotBlank(certificateProfile)) {
      throw new InvalidRequestException(
          "The CMS key and certificate handler does not support the profile: " + certificateProfile);
    }
  }

}
