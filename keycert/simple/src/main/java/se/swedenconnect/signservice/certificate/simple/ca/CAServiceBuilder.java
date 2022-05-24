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

import lombok.NonNull;
import org.bouncycastle.cert.X509CertificateHolder;
import se.swedenconnect.ca.engine.ca.issuer.CertificateIssuerModel;
import se.swedenconnect.ca.engine.ca.repository.CARepository;
import se.swedenconnect.ca.engine.revocation.crl.CRLIssuerModel;
import se.swedenconnect.ca.engine.revocation.crl.CRLRevocationDataProvider;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Calendar;
import java.util.List;

/**
 * CA service builder
 */
public class CAServiceBuilder {

  //Mandatory fields that must be set by the constructor
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
  /** The amount type specifying certificate validity (Default Year) */
  private int certificateValidityAmountType = Calendar.YEAR;

  /** The number of units a certificate should be valid (Default 1) */
  private int certificateValidityAmount = 1;

  /** The start time offset unit type from current time for certificate validity (Default Minute) */
  private int certificateStartOffsetAmountType = Calendar.MINUTE;

  /** The start time offset unit amount from current time for certificate validity (Default -15) */
  private int certificateStartOffsetAmount = -15;

  /** The amount type specifying CRL validity (Default Hour) */
  private int crlValidityAmountType = Calendar.HOUR;

  /** The number of units a CRL should be valid (Default 2) */
  private int crlValidityAmount = 2;

  /** The start time offset unit type from current time for CRL validity (Default Minute) */
  private int crlStartOffsetType = Calendar.MINUTE;

  /** The start time offset unit amount from current time for CRL validity (Default -15) */
  private int crlStartOffsetAmount = -15;

  /** private constructor */
  private CAServiceBuilder(@NonNull final PrivateKey privateKey,
    @NonNull final List<X509CertificateHolder> caCertificateChain,
    @NonNull final String crlDpUrl, @NonNull final String algorithm,
    final @NonNull CARepository caRepository) {
    if (caCertificateChain.size() < 1) {
      throw new IllegalArgumentException("CA certificate chain must not be empty");
    }
    this.privateKey = privateKey;
    this.caCertificateChain = caCertificateChain;
    this.crlDpUrl = crlDpUrl;
    this.algorithm = algorithm;
    this.caRepository = caRepository;
  }

  /**
   * Gets an instance of the CA service builder
   *
   * @param privateKey private CA key
   * @param caCertificateChain the certificate chain of the CA with the ca certificate as the first certificate
   * @param crlDpUrl the URL where the latest CRL published by this CA will be available
   * @param algorithm the signature algorithm of this CA
   * @param caRepository the repository for storing issued certificates and their status
   * @return instance of this CA service builder
   */
  public static CAServiceBuilder getInstance(final PrivateKey privateKey,
    final List<X509CertificateHolder> caCertificateChain, final String crlDpUrl, final String algorithm,
    final CARepository caRepository) {
    return new CAServiceBuilder(privateKey, caCertificateChain, crlDpUrl, algorithm, caRepository);
  }

  /**
   * Gets an instance of the CA service builder using the default NO data storage repository
   *
   * @param privateKey private CA key
   * @param caCertificateChain the certificate chain of the CA with the ca certificate as the first certificate
   * @param crlDpUrl the URL where the latest CRL published by this CA will be available
   * @param algorithm the signature algorithm of this CA
   * @param crlFile the file that will be used to write the latest CRL published by this CA
   * @return instance of this CA service builder
   */
  public static CAServiceBuilder getInstance(final PrivateKey privateKey,
    final List<X509CertificateHolder> caCertificateChain, final String crlDpUrl, final String algorithm,
    final @NonNull File crlFile) throws IOException {
    return new CAServiceBuilder(privateKey, caCertificateChain, crlDpUrl, algorithm,
      new NoStorageCARepository(crlFile));
  }

  /**
   * Build the CA service
   *
   * @return CA service
   * @throws NoSuchAlgorithmException if the specified algorithm was not supported
   */
  public BasicCAService build() throws NoSuchAlgorithmException {
    return new BasicCAService(privateKey, caCertificateChain, caRepository,
      getCertificateIssuerModel(), getCrlIssuerModel());
  }

  /**
   * Gets a certificate issuer model
   *
   * @return certificate issuer model
   * @throws NoSuchAlgorithmException algorithm is not supported
   */
  private CertificateIssuerModel getCertificateIssuerModel() throws NoSuchAlgorithmException {
    CertificateIssuerModel issuerModel = new CertificateIssuerModel(algorithm, certificateValidityAmount);
    issuerModel.setExpiryOffsetType(certificateValidityAmountType);
    issuerModel.setStartOffsetType(certificateStartOffsetAmountType);
    issuerModel.setStartOffsetAmount(certificateStartOffsetAmount);
    return issuerModel;
  }

  /**
   * Gets a CRL issuer model
   *
   * @return CRL issuer model
   */
  private CRLIssuerModel getCrlIssuerModel() {
    CRLRevocationDataProvider crlRevocationDataProvider = caRepository.getCRLRevocationDataProvider();
    CRLIssuerModel crlIssuerModel = new CRLIssuerModel(caCertificateChain.get(0), algorithm,
      crlValidityAmount, crlRevocationDataProvider, crlDpUrl);
    crlIssuerModel.setExpiryOffsetType(crlValidityAmountType);
    crlIssuerModel.setStartOffsetType(crlStartOffsetType);
    crlIssuerModel.setStartOffsetAmount(crlStartOffsetAmount);
    return crlIssuerModel;
  }

  /**
   * Setter for type of certificate validity units as Calendar unit type integers. E.g. set as Calendar.YEAR
   *
   * @param certificateValidityAmountType the amount type for certificate validity period
   * @return this builder
   */
  public CAServiceBuilder certificateValidityAmountType(int certificateValidityAmountType) {
    this.certificateValidityAmountType = certificateValidityAmountType;
    return this;
  }

  /**
   * Setter for the number of units for certificate validity of the specified type. E.g. the number of years or days
   *
   * @param certificateValidityAmount number of validity units
   * @return this builder
   */
  public CAServiceBuilder certificateValidityAmount(int certificateValidityAmount) {
    this.certificateValidityAmount = certificateValidityAmount;
    return this;
  }

  /**
   * Setter for type of certificate start offset time units as Calendar unit type integers. E.g. set as Calendar.MINUTE
   *
   * @param certificateStartOffsetAmountType
   * @return this builder
   */
  public CAServiceBuilder certificateStartOffsetAmountType(int certificateStartOffsetAmountType) {
    this.certificateStartOffsetAmountType = certificateStartOffsetAmountType;
    return this;
  }

  /**
   * Setter for the number of time units for start validity time offset. A negative amount specifies time in the past.
   *
   * @param certificateStartOffsetAmount number of time units to offset start time from current time
   * @return this builder
   */
  public CAServiceBuilder certificateStartOffsetAmount(int certificateStartOffsetAmount) {
    this.certificateStartOffsetAmount = certificateStartOffsetAmount;
    return this;
  }

  /**
   * Setter for type of CRL validity units as Calendar unit type integers. E.g. set as Calendar.YEAR
   *
   * @param crlValidityAmountType type of time units the CRL should be valid
   * @return this builder
   */
  public CAServiceBuilder crlValidityAmountType(int crlValidityAmountType) {
    this.crlValidityAmountType = crlValidityAmountType;
    return this;
  }

  /**
   * Setter for the number of time units for CRL validity of the specified type. E.g. the number of years or days
   *
   * @param crlValidityAmount amount of time units the CRL should be valid
   * @return this builder
   */
  public CAServiceBuilder crlValidityAmount(int crlValidityAmount) {
    this.crlValidityAmount = crlValidityAmount;
    return this;
  }

  /**
   * Setter for type of CRL start offset time units as Calendar unit type integers. E.g. set as Calendar.MINUTE
   *
   * @param crlStartOffsetType start time offset unit types for CRL validity
   * @return this builder
   */
  public CAServiceBuilder crlStartOffsetType(int crlStartOffsetType) {
    this.crlStartOffsetType = crlStartOffsetType;
    return this;
  }

  /**
   * Setter for the number of time units for start validity time offset. A negative amount specifies time in the past.
   *
   * @param crlStartOffsetAmount start time unit offset for CRL validity
   * @return this builder
   */
  public CAServiceBuilder crlStartOffsetAmount(int crlStartOffsetAmount) {
    this.crlStartOffsetAmount = crlStartOffsetAmount;
    return this;
  }

}
