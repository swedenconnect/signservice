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
package se.swedenconnect.signservice.certificate.simple.ca;

import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;
import se.swedenconnect.ca.engine.ca.repository.SortBy;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.crl.CRLRevocationDataProvider;
import se.swedenconnect.ca.engine.revocation.crl.RevokedCertificate;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * This CA repository does not store any certificates at all.
 * It may be useful for simple deployments where no revocation of certificates is provided
 * <p>
 * A crl file is however created in order to facilitate creation of an empty CRL
 */
public class NoStorageCARepository implements CARepository, CRLRevocationDataProvider {

  /** The current CRL number */
  private BigInteger crlNumber;

  /** CRL file for storing the latest CRL */
  private final File crlFile;

  /**
   * Constructor
   *
   * @param crlFile CRL file
   * @throws IOException error creating repository
   */
  public NoStorageCARepository(File crlFile) throws IOException {
    this.crlFile = crlFile;
    this.crlNumber = BigInteger.ZERO;
    if (crlFile.canRead()) {
      // If published CRL exists. Get CRL number from current CRL
      crlNumber = getCRLNumberFromCRL();
    }
  }

  private BigInteger getCRLNumberFromCRL() throws IOException {
    X509CRLHolder crlHolder = new X509CRLHolder(new FileInputStream(crlFile));
    Extension crlNumberExtension = crlHolder.getExtension(Extension.cRLNumber);
    CRLNumber crlNumberFromCrl = CRLNumber.getInstance(crlNumberExtension.getParsedValue());
    return crlNumberFromCrl.getCRLNumber();
  }

  /** {@inheritDoc} */
  @Override public List<BigInteger> getAllCertificates() {
    return new ArrayList<>();
  }

  /** {@inheritDoc} */
  @Override public CertificateRecord getCertificate(BigInteger serialNumber) {
    return null;
  }

  /** {@inheritDoc} */
  @Override public void addCertificate(X509CertificateHolder certificate) throws IOException {
  }

  /** {@inheritDoc} */
  @Override public void revokeCertificate(BigInteger serialNumber, int reason, Date revocationTime)
    throws CertificateRevocationException {
  }

  /** {@inheritDoc} */
  @Override public CRLRevocationDataProvider getCRLRevocationDataProvider() {
    return this;
  }

  /** {@inheritDoc} */
  @Override public int getCertificateCount(boolean notRevoked) {
    return 0;
  }

  /** {@inheritDoc} */
  @Override public List<CertificateRecord> getCertificateRange(int page, int pageSize, boolean notRevoked,
    SortBy sortBy, boolean descending) {
    return new ArrayList<>();
  }

  /** {@inheritDoc} */
  @Override public List<BigInteger> removeExpiredCerts(int gracePeriodSeconds) throws IOException {
    return new ArrayList<>();
  }

  /** {@inheritDoc} */
  @Override public List<RevokedCertificate> getRevokedCertificates() {
    return new ArrayList<>();
  }

  /** {@inheritDoc} */
  @Override public BigInteger getNextCrlNumber() {
    crlNumber = crlNumber.add(BigInteger.ONE);
    return crlNumber;
  }

  /** {@inheritDoc} */
  @SneakyThrows @Override public void publishNewCrl(X509CRLHolder crl) {
    FileUtils.writeByteArrayToFile(crlFile, crl.getEncoded());
  }

  /** {@inheritDoc} */
  @SneakyThrows @Override public X509CRLHolder getCurrentCrl() {
    return new X509CRLHolder(new FileInputStream(crlFile));
  }
}
