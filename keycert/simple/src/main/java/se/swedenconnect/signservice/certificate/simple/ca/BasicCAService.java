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

import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuer;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.issuer.impl.AbstractCAService;
import se.swedenconnect.ca.engine.ca.issuer.impl.BasicCertificateIssuer;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.extension.impl.simple.BasicConstraintsModel;
import se.swedenconnect.ca.engine.ca.models.cert.impl.DefaultCertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuer;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuerModel;
import se.swedenconnect.ca.engine.revocation.crl.impl.DefaultCRLIssuer;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Basic CA service implementation equipped to issue certificates to signers
 */
public class BasicCAService extends AbstractCAService<DefaultCertificateModelBuilder> {

  private final CertificateIssuer certificateIssuer;
  private CRLIssuer crlIssuer;
  private List<String> crlDistributionPoints;
  private OCSPResponder ocspResponder;
  private X509CertificateHolder ocspResponderCertificate;
  private String ocspResponderUrl;

  public BasicCAService(PrivateKey privateKey, List<X509CertificateHolder> caCertificateChain,
    CARepository caRepository, CertificateIssuerModel issuerModel, CRLIssuerModel crlIssuerModel)
    throws NoSuchAlgorithmException {
    super(caCertificateChain, caRepository);

    // Setup service
    this.certificateIssuer = new BasicCertificateIssuer(issuerModel, getCaCertificate().getSubject(), privateKey);
    this.crlDistributionPoints = new ArrayList<>();
    if (crlIssuerModel != null) {
      this.crlIssuer = new DefaultCRLIssuer(crlIssuerModel, privateKey);
      this.crlDistributionPoints = List.of(crlIssuerModel.getDistributionPointUrl());
      publishNewCrl();
    }
  }

  /** {@inheritDoc} */
  @Override public CertificateIssuer getCertificateIssuer() {
    return certificateIssuer;
  }

  /** {@inheritDoc} */
  @Override protected CRLIssuer getCrlIssuer() {
    return crlIssuer;
  }

  /** {@inheritDoc} */
  @Override
  public X509CertificateHolder getOCSPResponderCertificate() {
    return ocspResponderCertificate;
  }

  /** {@inheritDoc} */
  @Override
  public String getCaAlgorithm() {
    return certificateIssuer.getCertificateIssuerModel().getAlgorithm();
  }

  /** {@inheritDoc} */
  @Override
  public List<String> getCrlDpURLs() {
    return crlDistributionPoints;
  }

  /** {@inheritDoc} */
  @Override
  public String getOCSPResponderURL() {
    return ocspResponderUrl;
  }

  /**
   * Set OCSP responder for this CA service
   *
   * @param ocspResponder ocsp responder implementation
   * @param ocspResponderUrl URL for sending requests to the OCSP responder
   * @param ocspResponderCertificate OCSP responder certificate
   */
  public void setOcspResponder(OCSPResponder ocspResponder, String ocspResponderUrl,
    X509CertificateHolder ocspResponderCertificate) {
    this.ocspResponder = ocspResponder;
    this.ocspResponderUrl = ocspResponderUrl;
    this.ocspResponderCertificate = ocspResponderCertificate;
  }

  /** {@inheritDoc} */
  @Override
  public OCSPResponder getOCSPResponder() {
    return ocspResponder;
  }

  /** {@inheritDoc} */
  @Override
  protected DefaultCertificateModelBuilder getBaseCertificateModelBuilder(CertNameModel subject,
    PublicKey publicKey,
    X509CertificateHolder issuerCertificate, CertificateIssuerModel certificateIssuerModel)
    throws CertificateIssuanceException {
    DefaultCertificateModelBuilder certModelBuilder = DefaultCertificateModelBuilder.getInstance(publicKey,
      getCaCertificate(),
      certificateIssuerModel);
    certModelBuilder
      .subject(subject)
      .includeAki(true)
      .includeSki(true)
      .basicConstraints(new BasicConstraintsModel(false, true))
      .crlDistributionPoints(crlDistributionPoints.isEmpty() ? null : crlDistributionPoints)
      .ocspServiceUrl(ocspResponder != null ? ocspResponderUrl : null);
    return certModelBuilder;
  }

}
