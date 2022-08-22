/*
 * Copyright (c) 2021. Agency for Digital Government (DIGG)
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

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
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
import se.swedenconnect.ca.engine.revocation.crl.impl.DefaultCRLIssuer;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;
import se.swedenconnect.signservice.certificate.base.config.CertificateProfileConfiguration;
import se.swedenconnect.signservice.certificate.base.config.KeyUsageCalculator;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Basic CA service implementation equipped to issue certificates to signers.
 */
@Slf4j
public class BasicCAService extends AbstractCAService<DefaultCertificateModelBuilder> {

  private final CertificateIssuer certificateIssuer;
  private CRLIssuer crlIssuer;
  private List<String> crlDistributionPoints;
  private OCSPResponder ocspResponder;
  private X509CertificateHolder ocspResponderCertificate;
  private String ocspResponderUrl;

  /**
   * Optional certificate profile to be adopted in issued certificates.
   *
   * @param profileConfiguration certificate profile configuration
   */
  @Setter
  private CertificateProfileConfiguration profileConfiguration;

  /**
   * Constructor.
   *
   * @param privateKey private key of the CA service
   * @param caCertificateChain Certificate chain representing this CA with the ca certificate of this CA being the first
   *          certificate
   * @param caRepository repository for storing issued certificates
   * @param issuerModel model for issuing certificates
   * @param crlIssuerModel model for publishing CRL:s
   * @throws NoSuchAlgorithmException algorithm is not supported
   */
  public BasicCAService(final PrivateKey privateKey, final List<X509CertificateHolder> caCertificateChain,
      final CARepository caRepository, final CertificateIssuerModel issuerModel, final CRLIssuerModel crlIssuerModel)
      throws NoSuchAlgorithmException {
    super(caCertificateChain, caRepository);

    // Setup service
    this.certificateIssuer = new BasicCertificateIssuer(issuerModel, this.getCaCertificate().getSubject(), privateKey);
    this.crlDistributionPoints = new ArrayList<>();
    if (crlIssuerModel != null) {
      this.crlIssuer = new DefaultCRLIssuer(crlIssuerModel, privateKey);
      this.crlDistributionPoints = List.of(crlIssuerModel.getDistributionPointUrl());
      this.publishNewCrl();
    }
  }

  /** {@inheritDoc} */
  @Override
  public CertificateIssuer getCertificateIssuer() {
    return this.certificateIssuer;
  }

  /** {@inheritDoc} */
  @Override
  protected CRLIssuer getCrlIssuer() {
    return this.crlIssuer;
  }

  /** {@inheritDoc} */
  @Override
  public X509CertificateHolder getOCSPResponderCertificate() {
    return this.ocspResponderCertificate;
  }

  /** {@inheritDoc} */
  @Override
  public String getCaAlgorithm() {
    return this.certificateIssuer.getCertificateIssuerModel().getAlgorithm();
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getCrlDpURLs() {
    return this.crlDistributionPoints;
  }

  /** {@inheritDoc} */
  @Override
  public String getOCSPResponderURL() {
    return this.ocspResponderUrl;
  }

  /**
   * Set OCSP responder for this CA service
   *
   * @param ocspResponder ocsp responder implementation
   * @param ocspResponderUrl URL for sending requests to the OCSP responder
   * @param ocspResponderCertificate OCSP responder certificate
   */
  public void setOcspResponder(final OCSPResponder ocspResponder, final String ocspResponderUrl,
      final X509CertificateHolder ocspResponderCertificate) {
    this.ocspResponder = ocspResponder;
    this.ocspResponderUrl = ocspResponderUrl;
    this.ocspResponderCertificate = ocspResponderCertificate;
  }

  /** {@inheritDoc} */
  @Override
  public OCSPResponder getOCSPResponder() {
    return this.ocspResponder;
  }

  /** {@inheritDoc} */
  @Override
  protected DefaultCertificateModelBuilder getBaseCertificateModelBuilder(final CertNameModel subject,
      final PublicKey subjectPublicKey, final X509CertificateHolder issuerCertificate,
      final CertificateIssuerModel certificateIssuerModel)
      throws CertificateIssuanceException {

    final DefaultCertificateModelBuilder certModelBuilder = DefaultCertificateModelBuilder.getInstance(subjectPublicKey,
        this.getCaCertificate(),
        certificateIssuerModel);
    certModelBuilder
        .subject(subject)
        .includeAki(true)
        .includeSki(true)
        .crlDistributionPoints(this.crlDistributionPoints.isEmpty() ? null : this.crlDistributionPoints)
        .ocspServiceUrl(this.ocspResponder != null ? this.ocspResponderUrl : null);

    // Apply certificate profile
    updateProfileConfiguration(subjectPublicKey, certModelBuilder);


    return certModelBuilder;
  }

  private void updateProfileConfiguration(PublicKey subjectPublicKey, DefaultCertificateModelBuilder certModelBuilder) {
    CertificateProfileConfiguration conf = Optional.ofNullable(profileConfiguration).orElseGet(
      CertificateProfileConfiguration::getDefaultConfiguration);
    if (conf.getExtendedKeyUsages() != null && !conf.getExtendedKeyUsages().isEmpty()){
      certModelBuilder.extendedKeyUsage(new ExtendedKeyUsageModel(conf.getExtendedKeyUsageCritical(), conf.getExtendedKeyUsages().stream()
        .map(s -> KeyPurposeId.getInstance(new ASN1ObjectIdentifier(s)))
        .toArray(KeyPurposeId[]::new)
      ));
    }
    if (conf.getPolicy() != null && !conf.getPolicy().isEmpty()) {
      certModelBuilder.certificatePolicy(new CertificatePolicyModel(conf.getPolicyCritical(), conf.getPolicy().stream()
        .map(ASN1ObjectIdentifier::new)
        .toArray(ASN1ObjectIdentifier[]::new)
      ));
    }
    certModelBuilder
      .basicConstraints(new BasicConstraintsModel(false, conf.getBasicConstraintsCritical()))
      .keyUsage(new KeyUsageModel(KeyUsageCalculator.getKeyUsageValue(subjectPublicKey, conf.getUsageType())));
  }

}
