/*
 * Copyright 2022-2025 Sweden Connect
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
package se.swedenconnect.signservice.certificate.simple.ca;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.apache.commons.collections.CollectionUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.issuer.impl.AbstractCAService;
import se.swedenconnect.ca.engine.ca.issuer.impl.BasicCertificateIssuer;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.CertificatePolicyModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.ExtendedKeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuer;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuerModel;
import se.swedenconnect.ca.engine.revocation.crl.impl.SynchronizedCRLIssuer;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.certificate.base.config.CertificateProfileConfiguration;
import se.swedenconnect.signservice.certificate.base.config.KeyUsageCalculator;

/**
 * Basic CA service implementation equipped to issue certificates to signers.
 */
public class BasicCAService extends AbstractCAService<DefaultCertificateModelBuilder> {

  /** The certificate issuer component. */
  private final CertificateIssuer certificateIssuer;

  /** The CRL issuer component. */
  private CRLIssuer crlIssuer;

  /** The CRL distribution points. */
  private List<String> crlDistributionPoints;

  /** The OCSP responder. */
  private OCSPResponder ocspResponder;

  /** The certificate for the OCSP responder. */
  private X509Certificate ocspResponderCertificate;

  /** The URL that the OCSP responder listens to. */
  private String ocspResponderUrl;

  /**
   * Optional certificate profile to be adopted in issued certificates.
   */
  private CertificateProfileConfiguration profileConfiguration;

  /**
   * Constructor.
   *
   * @param caCredential the CA credential (private key and certificates)
   * @param caRepository repository for storing issued certificates
   * @param issuerModel model for issuing certificates
   * @param crlIssuerModel model for publishing CRL:s (optional)
   * @throws NoSuchAlgorithmException algorithm is not supported
   * @throws CertificateException for certificate errors
   * @throws CRLException if a CRL cannot be published
   */
  public BasicCAService(@Nonnull final PkiCredential caCredential,
      @Nonnull final CARepository caRepository, @Nonnull final CertificateIssuerModel issuerModel,
      @Nullable final CRLIssuerModel crlIssuerModel)
      throws NoSuchAlgorithmException, CertificateException, CRLException {
    super(caCredential, caRepository);

    // Setup service
    this.certificateIssuer = new BasicCertificateIssuer(issuerModel, caCredential);
    this.crlDistributionPoints = new ArrayList<>();
    if (crlIssuerModel != null) {
      this.crlIssuer = new SynchronizedCRLIssuer(crlIssuerModel, caRepository.getCRLRevocationDataProvider(), caCredential);
      this.crlDistributionPoints = List.of(crlIssuerModel.getDistributionPointUrl());
      try {
        this.publishNewCrl();
      }
      catch (final IOException e) {
        throw new CRLException("Failed to publish new CRL - " + e.getMessage(), e);
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public CertificateIssuer getCertificateIssuer() {
    return this.certificateIssuer;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  protected CRLIssuer getCrlIssuer() {
    return this.crlIssuer;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getCaAlgorithm() {
    return this.certificateIssuer.getCertificateIssuerModel().getAlgorithm();
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public List<String> getCrlDpURLs() {
    return this.crlDistributionPoints;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public X509CertificateHolder getOCSPResponderCertificate() {
    return Optional.ofNullable(this.ocspResponderCertificate)
        .map(BcFunctions.toX509CertificateHolder)
        .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public String getOCSPResponderURL() {
    return this.ocspResponderUrl;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public OCSPResponder getOCSPResponder() {
    return this.ocspResponder;
  }

  /**
   * Assigns the OCSP responder for this CA service.
   *
   * @param ocspResponder the OCSP responder implementation
   * @param ocspResponderUrl the URL for sending requests to the OCSP responder
   * @param ocspResponderCertificate the OCSP responder certificate
   */
  public void setOcspResponder(@Nonnull final OCSPResponder ocspResponder,
      @Nonnull final String ocspResponderUrl, @Nonnull final X509Certificate ocspResponderCertificate) {
    this.ocspResponder = Objects.requireNonNull(ocspResponder, "ocspResponder must not be null");
    this.ocspResponderUrl = Objects.requireNonNull(ocspResponderUrl, "ocspResponderUrl must not be null");
    this.ocspResponderCertificate =
        Objects.requireNonNull(ocspResponderCertificate, "ocspResponderCertificate must not be null");
  }

  /** {@inheritDoc} */
  @Override
  protected DefaultCertificateModelBuilder getBaseCertificateModelBuilder(
      @Nonnull final CertNameModel<?> subject, @Nonnull final PublicKey subjectPublicKey,
      @Nullable final X509CertificateHolder issuerCertificate,
      @Nonnull final CertificateIssuerModel certificateIssuerModel) throws CertificateIssuanceException {

    final DefaultCertificateModelBuilder certModelBuilder = DefaultCertificateModelBuilder.getInstance(
        subjectPublicKey,
        this.getCaCertificate(),
        certificateIssuerModel);

    certModelBuilder
        .subject(subject)
        .includeAki(true)
        .includeSki(true)
        .crlDistributionPoints(this.crlDistributionPoints.isEmpty() ? null : this.crlDistributionPoints)
        .ocspServiceUrl(this.ocspResponder != null ? this.ocspResponderUrl : null);

    // Apply certificate profile
    //
    final CertificateProfileConfiguration conf =
        Optional.ofNullable(this.profileConfiguration).orElseGet(() -> new CertificateProfileConfiguration());

    if (CollectionUtils.isNotEmpty(conf.getExtendedKeyUsages())) {
      certModelBuilder.extendedKeyUsage(new ExtendedKeyUsageModel(conf.isExtendedKeyUsageCritical(),
          conf.getExtendedKeyUsages().stream().map(s -> KeyPurposeId.getInstance(new ASN1ObjectIdentifier(s)))
              .toArray(KeyPurposeId[]::new)));
    }
    if (CollectionUtils.isNotEmpty(conf.getPolicies())) {
      certModelBuilder.certificatePolicy(new CertificatePolicyModel(conf.isPoliciesCritical(),
          conf.getPolicies().stream().map(ASN1ObjectIdentifier::new).toArray(ASN1ObjectIdentifier[]::new)));
    }
    certModelBuilder
        .basicConstraints(new BasicConstraintsModel(false, conf.isBasicConstraintsCritical()))
        .keyUsage(new KeyUsageModel(KeyUsageCalculator.getKeyUsageValue(subjectPublicKey, conf.getUsageDirective())));

    return certModelBuilder;
  }

  /**
   * Assigns the certificate profile to be adopted in issued certificates.
   *
   * @param profileConfiguration certificate profile configuration
   */
  public void setProfileConfiguration(@Nullable final CertificateProfileConfiguration profileConfiguration) {
    this.profileConfiguration = profileConfiguration;
  }

}
