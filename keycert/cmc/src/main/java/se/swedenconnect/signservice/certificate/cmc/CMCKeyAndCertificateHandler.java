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

package se.swedenconnect.signservice.certificate.cmc;

import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.cmc.api.client.CMCClient;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.AbstractCertificateModelBuilder;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.certificate.base.AbstractCaEngineKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.base.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.base.keyprovider.KeyProvider;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.session.SignServiceContext;

/**
 * CMC based key and certificate handler obtaining certificates from a remote CA using CMC
 */
@Slf4j
public class CMCKeyAndCertificateHandler extends AbstractCaEngineKeyAndCertificateHandler {

  /** CMC Client for remote CA service used to issue certificates */
  private final CMCClient cmcClient;

  /**
   * The certificate type produced by this certificate handler. Default PKC certificates
   */
  @Setter
  private CertificateType supportedCertificateType;

  /**
   * Constructor.
   *
   * @param keyProviders a list of key providers that this handler uses
   * @param attributeMapper the attribute mapper
   * @param cmcClient CMC client used to issue certificates using CMC
   */
  public CMCKeyAndCertificateHandler(
      @Nonnull final List<KeyProvider> keyProviders,
      @Nonnull final AttributeMapper attributeMapper,
      @Nonnull final CMCClient cmcClient) {
    super(keyProviders, attributeMapper);
    this.supportedCertificateType = CertificateType.PKC;
    this.cmcClient = Objects.requireNonNull(cmcClient, "cmcClient must not be null");
  }

  /**
   * Constructor.
   *
   * @param keyProviders a list of key providers that this handler uses
   * @param attributeMapper the attribute mapper
   * @param algorithmRegistry algorithm registry
   * @param cmcClient CMC client used to issue certificates using CMC
   */
  public CMCKeyAndCertificateHandler(
      @Nonnull final List<KeyProvider> keyProviders,
      @Nonnull final AttributeMapper attributeMapper,
      @Nonnull final AlgorithmRegistry algorithmRegistry,
      @Nonnull final CMCClient cmcClient) {
    super(keyProviders, attributeMapper, algorithmRegistry);
    this.supportedCertificateType = CertificateType.PKC;
    this.cmcClient = Objects.requireNonNull(cmcClient, "cmcClient must not be null");
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected X509Certificate issueSigningCertificate(@Nonnull final CertificateModel certificateModel,
      @Nonnull final SignServiceContext context) throws CertificateException {
    try {
      final CMCResponse cmcResponse = this.cmcClient.issueCertificate(certificateModel);
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
      return cmcResponse.getReturnCertificates().get(0);
    }
    catch (final IOException e) {
      final String msg = "Failed to complete CMC request - " + e.getMessage();
      log.info("{}", msg, e);
      throw new CertificateException(msg, e);
    }
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
    catch (final IOException e) {
      throw new CertificateException("Error obtaining certificate model from CMC client", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  protected void assertCertificateTypeSupported(@Nonnull final CertificateType certificateType,
      @Nullable final String certificateProfile) throws InvalidRequestException {
    if (!this.supportedCertificateType.equals(certificateType)) {
      throw new InvalidRequestException(
          "This CMC key and certificate handler can only produce certificates of type "
              + this.supportedCertificateType);
    }
  }

}
