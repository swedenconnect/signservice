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

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.time.Duration;
import java.util.Calendar;
import java.util.List;
import java.util.Objects;

import javax.annotation.Nonnull;

import org.bouncycastle.cert.X509CertificateHolder;

import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuerModel;
import se.swedenconnect.ca.engine.revocation.crl.CRLRevocationDataProvider;

/**
 * CA service builder
 */
public class CAServiceBuilder {

  /** Default certificate validity. */
  public static final Duration DEFAULT_CERTIFICATE_VALIDITY = Duration.ofDays(365);

  /** The default start time offset from current time for certificate validity. */
  public static final Duration DEFAULT_CERTIFICATE_START_OFFSET = Duration.ofMinutes(-15);

  /** Default CRL validity. */
  public static final Duration DEFAULT_CRL_VALIDITY = Duration.ofHours(2);

  /** The default start time offset from current time for CRL validity. */
  public static final Duration DEFAULT_CRL_START_OFFSET = Duration.ofMinutes(-15);

  // Mandatory fields that must be set by the constructor.

  /** The private key of the CA */
  private final PrivateKey privateKey;

  /** CA certificate chain */
  private final List<X509CertificateHolder> caCertificateChain;

  /** CRL Distribution point URL */
  private final String crlDpUrl;

  /** Algorithm used by the CA to sign certificates */
  private final String algorithm;

  /** The repository used by the CA to store certificates and revocation status */
  private final CARepository caRepository;

  // Fields that can be set by the builder setters

  /** The certificate validity period. */
  private Duration certificateValidity = DEFAULT_CERTIFICATE_VALIDITY;

  /** The start time offset from current time for certificate validity. */
  private Duration certificateStartOffset = DEFAULT_CERTIFICATE_START_OFFSET;

  /** The CRL validity period. */
  private Duration crlValidity = DEFAULT_CRL_VALIDITY;

  /** The start time offset from current time for CRL validity. */
  private Duration crlStartOffset = DEFAULT_CRL_START_OFFSET;

  // Private constructor
  private CAServiceBuilder(@Nonnull final PrivateKey privateKey,
      @Nonnull final List<X509CertificateHolder> caCertificateChain, @Nonnull final String crlDpUrl,
      @Nonnull final String algorithm, @Nonnull final CARepository caRepository) {

    this.privateKey = Objects.requireNonNull(privateKey, "privateKey must not be null");
    this.caCertificateChain = Objects.requireNonNull(caCertificateChain, "caCertificateChain must noy be null");
    if (this.caCertificateChain.isEmpty()) {
      throw new IllegalArgumentException("CA certificate chain must not be empty");
    }
    this.crlDpUrl = Objects.requireNonNull(crlDpUrl, "crlDpUrl must not be null");
    this.algorithm = Objects.requireNonNull(algorithm, "algorithm must noy be empty");
    this.caRepository = Objects.requireNonNull(caRepository, "caRepository must not be empty");
  }

  /**
   * Gets an instance of the CA service builder.
   *
   * @param privateKey private CA key
   * @param caCertificateChain the certificate chain of the CA with the ca certificate as the first certificate
   * @param crlDpUrl the URL where the latest CRL published by this CA will be available
   * @param algorithm the signature algorithm of this CA
   * @param caRepository the repository for storing issued certificates and their status
   * @return instance of this CA service builder
   */
  @Nonnull
  public static CAServiceBuilder getInstance(@Nonnull final PrivateKey privateKey,
      @Nonnull final List<X509CertificateHolder> caCertificateChain, @Nonnull final String crlDpUrl,
      @Nonnull final String algorithm, @Nonnull final CARepository caRepository) {
    return new CAServiceBuilder(privateKey, caCertificateChain, crlDpUrl, algorithm, caRepository);
  }

  /**
   * Gets an instance of the CA service builder using the default NO data storage repository.
   *
   * @param privateKey private CA key
   * @param caCertificateChain the certificate chain of the CA with the ca certificate as the first certificate
   * @param crlDpUrl the URL where the latest CRL published by this CA will be available
   * @param algorithm the signature algorithm of this CA
   * @param crlFile the file that will be used to write the latest CRL published by this CA
   * @return instance of this CA service builder
   * @throws IOException error getting instance
   */
  @Nonnull
  public static CAServiceBuilder getInstance(@Nonnull final PrivateKey privateKey,
      @Nonnull final List<X509CertificateHolder> caCertificateChain, @Nonnull final String crlDpUrl,
      @Nonnull final String algorithm, @Nonnull final File crlFile) throws IOException {
    return new CAServiceBuilder(privateKey, caCertificateChain, crlDpUrl, algorithm,
        new NoStorageCARepository(crlFile));
  }

  /**
   * Build the CA service.
   *
   * @return CA service
   * @throws NoSuchAlgorithmException if the specified algorithm was not supported
   */
  @Nonnull
  public BasicCAService build() throws NoSuchAlgorithmException {
    return new BasicCAService(this.privateKey, this.caCertificateChain, this.caRepository,
        this.getCertificateIssuerModel(), this.getCrlIssuerModel());
  }

  /**
   * Gets a certificate issuer model.
   *
   * @return certificate issuer model
   * @throws NoSuchAlgorithmException algorithm is not supported
   */
  @Nonnull
  private CertificateIssuerModel getCertificateIssuerModel() throws NoSuchAlgorithmException {
    final CertificateIssuerModel issuerModel =
        new CertificateIssuerModel(this.algorithm, (int) this.certificateValidity.getSeconds(), Calendar.SECOND);

    issuerModel.setStartOffsetType(Calendar.SECOND);
    issuerModel.setStartOffsetAmount((int) this.certificateStartOffset.getSeconds());
    return issuerModel;
  }

  /**
   * Gets a CRL issuer model.
   *
   * @return CRL issuer model
   */
  @Nonnull
  private CRLIssuerModel getCrlIssuerModel() {
    final CRLRevocationDataProvider crlRevocationDataProvider = this.caRepository.getCRLRevocationDataProvider();
    final CRLIssuerModel crlIssuerModel = new CRLIssuerModel(this.caCertificateChain.get(0), this.algorithm,
        (int) this.crlValidity.getSeconds(), crlRevocationDataProvider, this.crlDpUrl);
    crlIssuerModel.setExpiryOffsetType(Calendar.SECOND);
    crlIssuerModel.setStartOffsetType(Calendar.SECOND);
    crlIssuerModel.setStartOffsetAmount((int) this.crlStartOffset.getSeconds());
    return crlIssuerModel;
  }

  /**
   * Setter for certificate validity.
   *
   * @param certificateValidity the certificate validity period
   * @return this builder
   */
  @Nonnull
  public CAServiceBuilder certificateValidity(@Nonnull final Duration certificateValidity) {
    this.certificateValidity = Objects.requireNonNull(certificateValidity, "certificateValidity must not be null");
    return this;
  }

  /**
   * Setter for certificate start offset time.
   *
   * @param certificateStartOffset certificate start offset time
   * @return this builder
   */
  @Nonnull
  public CAServiceBuilder certificateStartOffset(@Nonnull final Duration certificateStartOffset) {
    this.certificateStartOffset =
        Objects.requireNonNull(certificateStartOffset, "certificateStartOffset must not be null");
    return this;
  }

  /**
   * Setter for CRL validity.
   *
   * @param crlValidity CRL validity
   * @return this builder
   */
  @Nonnull
  public CAServiceBuilder crlValidity(@Nonnull final Duration crlValidity) {
    this.crlValidity = Objects.requireNonNull(crlValidity, "crlValidity must not be null");
    return this;
  }

  /**
   * Setter for CRL start offset time.
   *
   * @param crlStartOffset start time offset for CRL validity
   * @return this builder
   */
  @Nonnull
  public CAServiceBuilder crlStartOffset(@Nonnull final Duration crlStartOffset) {
    this.crlStartOffset = Objects.requireNonNull(crlStartOffset, "crlStartOffset must not be null");
    return this;
  }

}
