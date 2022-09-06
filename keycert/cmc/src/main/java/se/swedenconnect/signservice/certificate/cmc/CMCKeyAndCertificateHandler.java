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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.commons.lang.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.certificate.CertificateUtils;
import se.swedenconnect.ca.cmc.api.client.CMCClient;
import se.swedenconnect.ca.cmc.api.data.CMCFailType;
import se.swedenconnect.ca.cmc.api.data.CMCResponse;
import se.swedenconnect.ca.cmc.api.data.CMCResponseStatus;
import se.swedenconnect.ca.cmc.api.data.CMCStatusType;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.AbstractCertificateModelBuilder;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.AlgorithmRegistrySingleton;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.base.AbstractCaEngineKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.keyprovider.KeyProvider;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.session.SignServiceContext;

/**
 * CMC based key and certificate handler obtaining certificates from a remote CA using CMC.
 */
@Slf4j
public class CMCKeyAndCertificateHandler extends AbstractCaEngineKeyAndCertificateHandler {

  /** CMC Client for remote CA service used to issue certificates. */
  private final CMCClient cmcClient;

  /** The CA chain. */
  private final List<X509Certificate> caChain;

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
    this(keyProviders, attributeMapper, AlgorithmRegistrySingleton.getInstance(), cmcClient);
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
    this.cmcClient = Objects.requireNonNull(cmcClient, "cmcClient must not be null");
    this.caChain = new ArrayList<>();
    try {
      for (final byte[] encoding : cmcClient.getStaticCAInformation().getCertificateChain()) {
        caChain.add(CertificateUtils.decodeCertificate(encoding));
      }
    }
    catch (final Exception e) {
      throw new SecurityException("Failed to get CA certificate chain", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected List<X509Certificate> issueSigningCertificateChain(@Nonnull final CertificateModel certificateModel,
      @Nullable final String certificateProfile, @Nonnull final SignServiceContext context)
      throws CertificateException {

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
      final List<X509Certificate> chain = new ArrayList<>();
      chain.add(cmcResponse.getReturnCertificates().get(0));
      chain.addAll(this.caChain);
      return chain;
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
  protected void assertCertificateProfileSupported(
      @Nullable final String certificateProfile) throws InvalidRequestException {
    if (StringUtils.isNotBlank(certificateProfile)) {
      throw new InvalidRequestException(
          "The CMS key and certificate handler does not support the profile: " + certificateProfile);
    }
  }

}
