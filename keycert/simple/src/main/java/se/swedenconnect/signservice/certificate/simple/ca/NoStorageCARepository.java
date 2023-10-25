/*
 * Copyright 2022-2023 Sweden Connect
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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.ca.repository.CertificateRecord;
import se.swedenconnect.ca.engine.ca.repository.SortBy;
import se.swedenconnect.ca.engine.revocation.CertificateRevocationException;
import se.swedenconnect.ca.engine.revocation.crl.CRLMetadata;
import se.swedenconnect.ca.engine.revocation.crl.CRLRevocationDataProvider;
import se.swedenconnect.ca.engine.revocation.crl.RevokedCertificate;

/**
 * This CA repository does not store any certificates at all. It may be useful for simple deployments where no
 * revocation of certificates is provided.
 * <p>
 * A CRL file is however created in order to facilitate creation of an empty CRL.
 * </p>
 */
@Slf4j
public class NoStorageCARepository implements CARepository, CRLRevocationDataProvider {

  /** The current CRL number. */
  private BigInteger crlNumber;

  /** CRL file for storing the latest CRL. */
  private final File crlFile;

  /**
   * Constructor.
   *
   * @param crlFileLocation CRL file location (the file does not have to exist)
   * @throws IOException error creating repository
   */
  public NoStorageCARepository(@Nonnull final String crlFileLocation) throws IOException {
    this.crlFile = new File(Objects.requireNonNull(crlFileLocation, "crlFileLocation must not be null"));
    this.crlNumber = BigInteger.ZERO;

    if (this.crlFile.canRead()) {
      // If published CRL exists. Get CRL number from current CRL.
      try (final InputStream is = new FileInputStream(this.crlFile)) {
        final X509CRLHolder crlHolder = new X509CRLHolder(is);
        final Extension crlNumberExtension = crlHolder.getExtension(Extension.cRLNumber);
        final CRLNumber crlNumberFromCrl = CRLNumber.getInstance(crlNumberExtension.getParsedValue());
        this.crlNumber = crlNumberFromCrl.getCRLNumber();
      }
    }
  }

  /**
   * Will always return an empty list.
   */
  @Override
  @Nonnull
  public List<BigInteger> getAllCertificates() {
    return Collections.emptyList();
  }

  /**
   * Will always return {@code null}.
   */
  @Override
  @Nullable
  public CertificateRecord getCertificate(@Nonnull final BigInteger serialNumber) {
    return null;
  }

  /**
   * Does nothing.
   */
  @Override
  public void addCertificate(@Nonnull final X509CertificateHolder certificate) throws IOException {
  }

  /**
   * Does nothing.
   */
  @Override
  public void revokeCertificate(@Nonnull final BigInteger serialNumber, @Nonnull final int reason,
      @Nonnull final Date revocationTime) throws CertificateRevocationException {
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public CRLRevocationDataProvider getCRLRevocationDataProvider() {
    return this;
  }

  /**
   * Will always return 0.
   */
  @Override
  public int getCertificateCount(final boolean notRevoked) {
    return 0;
  }

  /**
   * Will always return 0.
   */
  @Override
  @Nonnull
  public List<CertificateRecord> getCertificateRange(final int page, final int pageSize, final boolean notRevoked,
      final SortBy sortBy, final boolean descending) {
    return Collections.emptyList();
  }

  /**
   * Will always return an empty list.
   */
  @Override
  @Nonnull
  public List<BigInteger> removeExpiredCerts(final int gracePeriodSeconds) throws IOException {
    return Collections.emptyList();
  }

  /**
   * Will always return an empty list.
   */
  @Override
  @Nonnull
  public List<RevokedCertificate> getRevokedCertificates() {
    return Collections.emptyList();
  }

  /** {@inheritDoc} */
  @Override
  public BigInteger getNextCrlNumber() {
    this.crlNumber = this.crlNumber.add(BigInteger.ONE);
    return this.crlNumber;
  }

  /** {@inheritDoc} */
  @Override
  public void publishNewCrl(@Nonnull final X509CRLHolder crl) throws IOException {
    FileUtils.writeByteArrayToFile(this.crlFile, crl.getEncoded());
  }

  /** {@inheritDoc} */
  @Override
  public X509CRLHolder getCurrentCrl() {
    try {
      return new X509CRLHolder(new FileInputStream(this.crlFile));
    }
    catch (final Exception e) {
      log.debug("No current CRL is available. Returning null");
      return null;
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public CRLMetadata getCurrentCRLMetadata() {
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
