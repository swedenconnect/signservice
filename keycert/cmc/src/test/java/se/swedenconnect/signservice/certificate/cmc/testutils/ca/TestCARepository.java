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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;
import se.swedenconnect.ca.engine.ca.repository.SortBy;
import se.swedenconnect.ca.engine.ca.repository.impl.SerializableCertificateRecord;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.crl.CRLMetadata;
import se.swedenconnect.ca.engine.revocation.crl.CRLRevocationDataProvider;
import se.swedenconnect.ca.engine.revocation.crl.RevokedCertificate;

/**
 * Test implementation of a CA repository
 */
@Slf4j
public class TestCARepository implements CARepository, CRLRevocationDataProvider {

  private final File crlFile;
  private List<CertificateRecord> issuedCerts;
  private BigInteger crlNumber;

  public TestCARepository(File crlFile) {
    this.crlFile = crlFile;
    this.issuedCerts = new ArrayList<>();
    this.crlNumber = BigInteger.ZERO;
  }

  @Override public List<BigInteger> getAllCertificates() {
    return issuedCerts.stream()
      .map(certificateRecord -> certificateRecord.getSerialNumber())
      .collect(Collectors.toList());
  }

  @Override public CertificateRecord getCertificate(BigInteger bigInteger) {
    Optional<CertificateRecord> recordOptional = issuedCerts.stream()
      .filter(certificateRecord -> certificateRecord.getSerialNumber().equals(bigInteger))
      .findFirst();
    return recordOptional.isPresent() ? recordOptional.get() : null;
  }

  @Override public void addCertificate(X509CertificateHolder certificate) throws IOException {
    CertificateRecord record = getCertificate(certificate.getSerialNumber());
    if (record != null) {
      throw new IOException("This certificate already exists in the certificate repository");
    }
    issuedCerts.add(new SerializableCertificateRecord(certificate.getEncoded(), certificate.getSerialNumber(),
      certificate.getNotBefore(), certificate.getNotAfter(), false, null, null));
  }

  @Override public void revokeCertificate(BigInteger serialNumber, int reason, Date revocationTime) throws CertificateRevocationException {
    if (serialNumber == null) {
      throw new CertificateRevocationException("Null Serial number");
    }
    CertificateRecord certificateRecord = getCertificate(serialNumber);
    if (certificateRecord == null) {
      throw new CertificateRevocationException("No such certificate (" + serialNumber.toString(16) + ")");
    }
    certificateRecord.setRevoked(true);
    certificateRecord.setReason(reason);
    certificateRecord.setRevocationTime(revocationTime);
  }

  @Override public CRLRevocationDataProvider getCRLRevocationDataProvider() {
    return this;
  }

  @Override public List<RevokedCertificate> getRevokedCertificates() {
    return issuedCerts.stream()
      .filter(certificateRecord -> certificateRecord.isRevoked())
      .map(certificateRecord -> new RevokedCertificate(
        certificateRecord.getSerialNumber(),
        certificateRecord.getRevocationTime(),
        certificateRecord.getReason()
      ))
      .collect(Collectors.toList());
  }

  @Override public BigInteger getNextCrlNumber() {
    crlNumber = crlNumber.add(BigInteger.ONE);
    return crlNumber;
  }

  @Override public int getCertificateCount(boolean valid) {
    if (!valid) {
      return issuedCerts.size();
    }

    return (int) issuedCerts.stream()
      .filter(certificateRecord -> !certificateRecord.isRevoked())
      .count();
  }

  @Override public List<CertificateRecord> getCertificateRange(int page, int pageSize, boolean valid, SortBy sortBy, boolean descending) {

    List<CertificateRecord> records = issuedCerts.stream()
      .filter(certificateRecord -> {
        if (valid) {
          return !certificateRecord.isRevoked();
        }
        return true;
      })
      .collect(Collectors.toList());

    if (sortBy != null) {
      switch (sortBy) {
      case serialNumber:
        records.sort(Comparator.comparing(CertificateRecord::getSerialNumber));
        break;
      case issueDate:
        records.sort(Comparator.comparing(CertificateRecord::getIssueDate));
        break;
      }
    }

    if (descending) {
      Collections.reverse(records);
    }

    int startIdx = page * pageSize;
    int endIdx = startIdx + pageSize;

    if (startIdx > records.size()){
      return new ArrayList<>();
    }

    if (endIdx > records.size()) {
      endIdx = records.size();
    }

    List<CertificateRecord> resultCertList = new ArrayList<>();
    for (int i = startIdx; i<endIdx;i++) {
      resultCertList.add(records.get(i));
    }

    return resultCertList;
  }

  @Override public synchronized List<BigInteger> removeExpiredCerts(int gracePeriodSeconds) {
    List<BigInteger> removedSerialList = new ArrayList<>();
    Date notBefore = new Date(System.currentTimeMillis() - (1000 * gracePeriodSeconds));
    issuedCerts = issuedCerts.stream()
      .filter(certificateRecord -> {
        final Date expiryDate = certificateRecord.getExpiryDate();
        // Check if certificate expired before the current time minus grace period
        if (expiryDate.before(notBefore)){
          // Yes - Remove certificate
          removedSerialList.add(certificateRecord.getSerialNumber());
          return false;
        }
        // No - keep certificate on repository
        return true;
      })
      .collect(Collectors.toList());
    return removedSerialList;
  }


  @Override public void publishNewCrl(X509CRLHolder crl) throws IOException {
    FileUtils.writeByteArrayToFile(crlFile, crl.getEncoded());
  }

  @Override public X509CRLHolder getCurrentCrl() {
    try {
      return new X509CRLHolder(new FileInputStream(crlFile));
    }
    catch (IOException e) {
      log.debug("No current CRL is available");
      return null;
    }
  }

  @Override public CRLMetadata getCurrentCRLMetadata() {
    final X509CRLHolder currentCrl = getCurrentCrl();
    if (currentCrl == null) {
      log.debug("No CRL file is available - Resetting CRL metadata to support initial CRL creation");
      // No CRL is available. Return empty metadata to allow initial CRL creation;
      return CRLMetadata.builder()
        .crlNumber(BigInteger.ZERO)
        .issueTime(Instant.ofEpochMilli(0L))
        .nextUpdate(Instant.ofEpochMilli(0L))
        .revokedCertCount(0)
        .build();
    }

    log.debug("Returning CRL metadata from current CRL");
    return CRLMetadata.builder()
      .crlNumber(crlNumber)
      .issueTime(currentCrl.getThisUpdate().toInstant())
      .nextUpdate(currentCrl.getNextUpdate().toInstant())
      .revokedCertCount(currentCrl.getRevokedCertificates().size())
      .build();
  }
}
