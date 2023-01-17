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
package se.swedenconnect.signservice.certificate.cmc.testutils.ca;

import java.io.File;
import java.security.PublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.issuer.impl.AbstractCAService;
import se.swedenconnect.ca.engine.ca.issuer.impl.BasicCertificateIssuer;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.data.AttributeMappingBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.data.SAMLAuthContextBuilder;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.KeyUsageModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuer;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuerModel;
import se.swedenconnect.ca.engine.revocation.crl.CRLRevocationDataProvider;
import se.swedenconnect.ca.engine.revocation.crl.impl.SynchronizedCRLIssuer;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;
import se.swedenconnect.cert.extensions.data.saci.AttributeMapping;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * CA service for test
 */
public class TestCAService extends AbstractCAService<DefaultCertificateModelBuilder> {

  private final File crlFile;
  private final CertificateIssuer certificateIssuer;
  private CRLIssuer crlIssuer;
  private List<String> crlDistributionPoints;
  private OCSPResponder ocspResponder;
  private X509CertificateHolder ocspResponderCertificate;
  private String ocspResponderUrl;

  public TestCAService(final PkiCredential caCredential, final CARepository caRepository, final File crlFile,
      final String algorithm)
      throws Exception {
    super(caCredential, caRepository);
    this.crlFile = crlFile;
    this.certificateIssuer =
        new BasicCertificateIssuer(new CertificateIssuerModel(algorithm, Duration.ofDays(365)), caCredential);
    final CRLIssuerModel crlIssuerModel =
        this.getCrlIssuerModel(this.getCaRepository().getCRLRevocationDataProvider(), algorithm);
    this.crlDistributionPoints = new ArrayList<>();
    if (crlIssuerModel != null) {
      this.crlIssuer = new SynchronizedCRLIssuer(crlIssuerModel, caRepository.getCRLRevocationDataProvider(), caCredential);
      this.crlDistributionPoints = Arrays.asList(crlIssuerModel.getDistributionPointUrl());
      this.publishNewCrl();
    }
  }

  private CRLIssuerModel getCrlIssuerModel(final CRLRevocationDataProvider crlRevocationDataProvider,
      final String algorithm)
      throws CertificateRevocationException {
    try {
      return new CRLIssuerModel(this.getCaCertificate(), algorithm, Duration.ofDays(2),
          TestCAHolder.getFileUrl(this.crlFile));
    }
    catch (final Exception e) {
      throw new CertificateRevocationException(e);
    }
  }

  @Override
  public CertificateIssuer getCertificateIssuer() {
    return this.certificateIssuer;
  }

  @Override
  protected CRLIssuer getCrlIssuer() {
    return this.crlIssuer;
  }

  public void setOcspResponder(final OCSPResponder ocspResponder, final String ocspResponderUrl,
      final X509CertificateHolder ocspResponderCertificate) {
    this.ocspResponder = ocspResponder;
    this.ocspResponderUrl = ocspResponderUrl;
    this.ocspResponderCertificate = ocspResponderCertificate;
  }

  @Override
  public OCSPResponder getOCSPResponder() {
    return this.ocspResponder;
  }

  @Override
  public X509CertificateHolder getOCSPResponderCertificate() {
    return this.ocspResponderCertificate;
  }

  @Override
  public String getCaAlgorithm() {
    return this.certificateIssuer.getCertificateIssuerModel().getAlgorithm();
  }

  @Override
  public List<String> getCrlDpURLs() {
    return this.crlDistributionPoints;
  }

  @Override
  public String getOCSPResponderURL() {
    return this.ocspResponderUrl;
  }

  @Override
  protected DefaultCertificateModelBuilder getBaseCertificateModelBuilder(final CertNameModel<?> subject,
      final PublicKey publicKey,
      final X509CertificateHolder issuerCertificate, final CertificateIssuerModel certificateIssuerModel)
      throws CertificateIssuanceException {
    final DefaultCertificateModelBuilder certModelBuilder =
        DefaultCertificateModelBuilder.getInstance(publicKey, this.getCaCertificate(),
            certificateIssuerModel);
    certModelBuilder
        .subject(subject)
        .includeAki(true)
        .includeSki(true)
        .basicConstraints(new BasicConstraintsModel(true, true))
        .keyUsage(new KeyUsageModel(KeyUsage.digitalSignature))
        .crlDistributionPoints(this.crlDistributionPoints.isEmpty() ? null : this.crlDistributionPoints)
        .ocspServiceUrl(this.ocspResponder != null ? this.ocspResponderUrl : null)
        .authenticationContext(SAMLAuthContextBuilder.instance()
            .assertionRef("1234567890")
            .serviceID("SignService")
            .authenticationInstant(new Date())
            .authnContextClassRef("http://id.example.com/loa3")
            .attributeMappings(Arrays.asList(AttributeMappingBuilder.instance()
                .friendlyName("commonName")
                .name("urn:oid:2.5.4.3")
                .nameFormat("http://example.com/nameFormatUri")
                .ref("1.2.3.4")
                .type(AttributeMapping.Type.rdn)
                .build()))
            .build());
    return certModelBuilder;
  }

}
