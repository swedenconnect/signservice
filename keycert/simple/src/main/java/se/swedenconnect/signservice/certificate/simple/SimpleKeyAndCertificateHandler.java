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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.AbstractCertificateModelBuilder;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.credential.container.PkiCredentialContainer;
import se.swedenconnect.signservice.certificate.attributemapping.AttributeMapper;
import se.swedenconnect.signservice.certificate.base.AbstractCaEngineKeyAndCertificateHandler;
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

  /** The CA chain. */
  private final List<X509Certificate> caChain;

  /**
   * Constructor.
   *
   * @param keyProvider a {@link PkiCredentialContainer} acting as the source of generated signing keys
   * @param algorithmKeyTypes a map of the selected key type for each supported algorithm
   * @param attributeMapper attribute mapper
   * @param algorithmRegistry algorithm registry
   * @param caService ca service
   * @param crlPublishPath the path (relative) to the application root where CRL:s are exposed
   */
  public SimpleKeyAndCertificateHandler(
      @Nonnull final PkiCredentialContainer keyProvider,
      @Nullable final Map<String, String> algorithmKeyTypes,
      @Nonnull final AttributeMapper attributeMapper,
      @Nullable final AlgorithmRegistry algorithmRegistry,
      @Nonnull final CAService caService,
      @Nullable final String crlPublishPath) {
    super(keyProvider, algorithmKeyTypes, attributeMapper, algorithmRegistry);
    this.caService = Objects.requireNonNull(caService, "caService must not be null");
    this.crlPublishPath = crlPublishPath;
    this.caChain = new ArrayList<>();
    try {
      for (final X509CertificateHolder c : this.caService.getCACertificateChain()) {
        this.caChain.add(CertificateUtils.decodeCertificate(c.getEncoded()));
      }
    }
    catch (final CertificateException | IOException e) {
      throw new SecurityException("Failed to get CA certificate chain", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected List<X509Certificate> issueSigningCertificateChain(@Nonnull final CertificateModel certificateModel,
      @Nullable final String certificateProfile, @Nonnull final SignServiceContext context)
      throws CertificateException {

    log.debug("Issuing certificate from certificate model");
    try {
      final X509CertificateHolder certificateHolder = this.caService.issueCertificate(certificateModel);
      List<X509Certificate> chain = new ArrayList<>();
      chain.add(CertificateUtils.decodeCertificate(certificateHolder.getEncoded()));
      chain.addAll(this.caChain);
      return chain;
    }
    catch (final CertificateIssuanceException e) {
      final String msg = String.format("Failed to issue certificate - %s", e.getMessage());
      log.info("{}", msg, e);
      throw new CertificateException(msg, e);
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
    try {
      return (AbstractCertificateModelBuilder<? extends AbstractCertificateModelBuilder<?>>) this.caService
          .getCertificateModelBuilder(subject, subjectPublicKey);
    }
    catch (final CertificateIssuanceException e) {
      throw new CertificateException("Failed to get certificate model builder - " + e.getMessage(), e);
    }
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
    return this.crlPublishPath != null && this.crlPublishPath.equalsIgnoreCase(httpRequest.getServletPath());
  }

}
