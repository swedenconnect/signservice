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
package se.swedenconnect.signservice.certificate.cmc.testutils.ca;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Date;
import java.util.List;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;

import se.swedenconnect.ca.engine.ca.issuer.CAService;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuanceException;
import se.swedenconnect.ca.engine.ca.models.cert.CertNameModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModel;
import se.swedenconnect.ca.engine.ca.models.cert.CertificateModelBuilder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.ocsp.OCSPResponder;

/**
 * A bad CA service that issue null certificates
 */
public class BadCAService implements CAService{

  final CAService ca;

  public BadCAService(CAService ca) {
    this.ca = ca;
  }

  @Override public CertificateModelBuilder getCertificateModelBuilder(CertNameModel<?> certNameModel,
    PublicKey publicKey) throws CertificateIssuanceException {
    return ca.getCertificateModelBuilder(certNameModel, publicKey);
  }

  @Override public X509CertificateHolder issueCertificate(CertificateModel certificateModel)
    throws CertificateIssuanceException {
    return null;
  }

  @Override public void revokeCertificate(BigInteger bigInteger, Date date) throws CertificateRevocationException {
  }

  @Override public void revokeCertificate(BigInteger bigInteger, int i, Date date)
    throws CertificateRevocationException {
  }

  @Override public X509CRLHolder publishNewCrl() throws CertificateRevocationException {
    return null;
  }

  @Override public X509CRLHolder getCurrentCrl() {
    return null;
  }

  @Override public X509CertificateHolder getCaCertificate() {
    return ca.getCaCertificate();
  }

  @Override public List<X509CertificateHolder> getCACertificateChain() {
    return ca.getCACertificateChain();
  }

  @Override public CARepository getCaRepository() {
    return ca.getCaRepository();
  }

  @Override public OCSPResponder getOCSPResponder() {
    return ca.getOCSPResponder();
  }

  @Override public X509CertificateHolder getOCSPResponderCertificate() {
    return ca.getOCSPResponderCertificate();
  }

  @Override public String getCaAlgorithm() {
    return ca.getCaAlgorithm();
  }

  @Override public List<String> getCrlDpURLs() {
    return ca.getCrlDpURLs();
  }

  @Override public String getOCSPResponderURL() {
    return ca.getOCSPResponderURL();
  }
}
