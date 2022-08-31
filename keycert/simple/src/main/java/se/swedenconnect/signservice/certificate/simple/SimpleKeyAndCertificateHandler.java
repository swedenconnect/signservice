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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.certificate.CertificateUtils;
import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.AbstractCertificateModelBuilder;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.base.AbstractCaEngineKeyAndCertificateHandler;
import se.swedenconnect.signservice.certificate.keyprovider.KeyProvider;
import se.swedenconnect.signservice.core.http.HttpResourceProvider;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.session.SignServiceContext;

/**
 * A simple key and certificate handler.
 */
@Slf4j
public class SimpleKeyAndCertificateHandler extends AbstractCaEngineKeyAndCertificateHandler
    implements HttpResourceProvider {

  /** CA service used to issue certificates */
  private final CAService caService;

  /** The CRL publishing path. */
  private final String crlPublishPath;

  /**
   * Constructor.
   *
   * @param keyProviders a list of key providers that this handler uses
   * @param attributeMapper attribute mapper
   * @param caService ca service
   * @param crlPublishPath the path (relative) to the application root where CRL:s are exposed
   */
  public SimpleKeyAndCertificateHandler(
      @Nonnull final List<KeyProvider> keyProviders,
      @Nonnull final AttributeMapper attributeMapper,
      @Nonnull final CAService caService,
      @Nonnull final String crlPublishPath) {
    super(keyProviders, attributeMapper);
    this.caService = Objects.requireNonNull(caService, "caService must not be null");
    this.crlPublishPath = Objects.requireNonNull(crlPublishPath, "crlPublishPath must not be null");
  }

  /**
   * Constructor.
   *
   * @param keyProviders a list of key providers that this handler uses
   * @param attributeMapper attribute mapper
   * @param algorithmRegistry algorithm registry
   * @param caService ca service
   * @param crlPublishPath the path (relative) to the application root where CRL:s are exposed
   */
  public SimpleKeyAndCertificateHandler(
      @Nonnull final List<KeyProvider> keyProviders,
      @Nonnull final AttributeMapper attributeMapper,
      @Nonnull final AlgorithmRegistry algorithmRegistry,
      @Nonnull final CAService caService,
      @Nonnull final String crlPublishPath) {
    super(keyProviders, attributeMapper, algorithmRegistry);
    this.caService = Objects.requireNonNull(caService, "caService must not be null");
    this.crlPublishPath = Objects.requireNonNull(crlPublishPath, "crlPublishPath must not be null");
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected X509Certificate issueSigningCertificate(@Nonnull final CertificateModel certificateModel,
      @Nullable final String certificateProfile, @Nonnull final SignServiceContext context)
      throws CertificateException {

    log.debug("Issuing certificate from certificate model");
    final X509CertificateHolder certificateHolder = this.caService.issueCertificate(certificateModel);
    try {
      return CertificateUtils.decodeCertificate(certificateHolder.getEncoded());
    }
    catch (final IOException e) {
      final String msg = "Failed to decode issued X509 certificate";
      log.info("{}", e);
      throw new CertificateException(msg, e);
    }
  }

  /** {@inheritDoc} */
  @SuppressWarnings("unchecked")
  @Override
  @Nonnull
  protected AbstractCertificateModelBuilder<? extends AbstractCertificateModelBuilder<?>> createCertificateModelBuilder(
      @Nonnull final PublicKey subjectPublicKey, @Nonnull final CertNameModel<?> subject) throws CertificateException {
    return (AbstractCertificateModelBuilder<? extends AbstractCertificateModelBuilder<?>>) this.caService
        .getCertificateModelBuilder(subject, subjectPublicKey);
  }

  /** {@inheritDoc} */
  @Override
  protected void assertCertificateProfileSupported(
      @Nullable final String certificateProfile) throws InvalidRequestException {
    if (StringUtils.isNotBlank(certificateProfile)) {
      throw new InvalidRequestException("This handler does not support profile: " + certificateProfile);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void getResource(@Nonnull final HttpServletRequest httpRequest,
      @Nonnull final HttpServletResponse httpResponse) throws IOException {

    log.debug("Request to download CRL [{}]", httpRequest.getRemoteAddr());

    if (!this.supports(httpRequest)) {
      log.info("Invalid call to getResource on {}", this.getClass().getSimpleName());
      throw new IOException("Invalid call");
    }
    final X509CRLHolder crl = this.caService.getCurrentCrl();

    httpResponse.setContentType("application/octet-stream");
    httpResponse.setHeader("Content-disposition", "attachment; filename=cacrl.crl");

    try (final ByteArrayInputStream bis = new ByteArrayInputStream(crl.getEncoded());
        final OutputStream os = httpResponse.getOutputStream()) {
      final byte[] buffer = new byte[4096];
      int numBytesRead;
      while ((numBytesRead = bis.read(buffer)) > 0) {
          os.write(buffer, 0, numBytesRead);
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean supports(@Nonnull final HttpServletRequest httpRequest) {
    if (!"GET".equals(httpRequest.getMethod())) {
      return false;
    }
    return this.crlPublishPath.equalsIgnoreCase(httpRequest.getRequestURI());
  }

}
