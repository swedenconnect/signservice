/*
 * Copyright 2022-2024 Sweden Connect
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
package se.swedenconnect.signservice.signature.tbsdata;

import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.signservice.core.config.ValidationConfiguration;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.signature.AdESObject;
import se.swedenconnect.signservice.signature.AdESType;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;

/**
 * Abstract implementation of TBS data processor
 */
@Slf4j
public abstract class AbstractTBSDataProcessor implements TBSDataProcessor {

  /**
   * Defines if processing of input data is strict or applies the Postel's robustness principle. An example of this is
   * that a PAdES signature MUST NOT contain signing time in signed attributes. With strict processing a request with
   * signing time will fail. By default, such request will be accepted, but the signing time will be removed in line
   * with the PAdES standard.
   */
  @Setter
  private boolean strictProcessing = false;

  /**
   * Defines if ESSCertID holding a hash of the signer certificate should include Issuer Serial data in addition to the
   * certificate hash
   */
  @Setter
  private boolean includeIssuerSerial = false;

  /** Supported processing rules */
  private final List<String> supportedProcessingRules;

  /** The clock skew that we accept during checks of time stamps. */
  @Setter
  protected Duration allowedClockSkew = ValidationConfiguration.DEFAULT_ALLOWED_CLOCK_SKEW;

  /**
   * The maximum amount of time that has passed since a message we are receiving was sent. This is based on the
   * message's "created-at" property (or similar).
   */
  @Setter
  protected Duration maxMessageAge = ValidationConfiguration.DEFAULT_MAX_MESSAGE_AGE;

  /**
   * Constructor.
   *
   * @param supportedProcessingRules list of processing rule identifiers supported by this TBS data processor
   */
  public AbstractTBSDataProcessor(@Nullable final List<String> supportedProcessingRules) {
    this.supportedProcessingRules = Optional.ofNullable(supportedProcessingRules)
        .orElseGet(() -> Collections.emptyList());
  }

  /**
   * Check processing rules of this TBS data processor against requested processing rule.
   *
   * @param processingRulesUri requested processing rule
   * @throws SignatureException on error processing according to the required processing rule
   */
  protected void defaultProcessingRuleCheck(@Nullable final String processingRulesUri) throws SignatureException {
    if (processingRulesUri == null && this.supportedProcessingRules.isEmpty()) {
      log.debug("Using default processing rules");
    }
    else {
      if (processingRulesUri != null) {
        if (this.supportedProcessingRules.contains(processingRulesUri)) {
          log.debug("Using supported processing rule: {}", processingRulesUri);
        }
        else {
          throw new SignatureException(String.format(
              "Processing rule %s is not supported. Expected one of %s", processingRulesUri,
              this.supportedProcessingRules));
        }
      }
      else {
        log.debug("Null requested processing rule is accepted among supported processing rules. {}",
            this.supportedProcessingRules);
      }
    }
  }

  /**
   * Check signing time provided in the sign request
   *
   * @param signingTime signing time
   * @throws InvalidRequestException for invalid input
   */
  protected void checkSigningTime(@Nonnull final Instant signingTime) throws InvalidRequestException {
    final Instant now = Instant.now();
    // Maximum time into the future  allowed for signing time.
    final Instant notAfter = now.plusMillis(this.allowedClockSkew.toMillis());
    // Maximum time in the past allowed for signing time.
    final Instant notBefore = now.minusMillis(this.maxMessageAge.toMillis())
      .minusMillis(this.allowedClockSkew.toMillis());
    if (signingTime.isAfter(notAfter)){
      throw new InvalidRequestException("Signature request contains an illegal signing time (future date)");
    }
    if (signingTime.isBefore(notBefore)){
      throw new InvalidRequestException("Signature request contains an illegal signing time (too old)");
    }
  }

  /** {@inheritDoc} */
  @Override
  public TBSProcessingData processSignTaskData(@Nonnull final RequestedSignatureTask signatureTask,
      @Nonnull final X509Certificate signerCertificate, @Nonnull final SignatureAlgorithm signatureAlgorithm)
      throws SignatureException {
    // Note that on this level absence of any input parameter is considered a programming error and produces
    // an unchecked NullPointerException
    Objects.requireNonNull(signatureTask, "SignatureTask must not be null");
    Objects.requireNonNull(signerCertificate, "Signer certificate must not be null");
    Objects.requireNonNull(signatureAlgorithm, "Signature algorithm must not be null");

    try {
      // Validate the input data
      this.checkSignTask(signatureTask, signatureAlgorithm);
    }
    catch (final InvalidRequestException e) {
      // Convert invalid request to SignatureException
      throw new SignatureException(e.getMessage());
    }

    return this.processSignatureTypeTBSData(signatureTask, signerCertificate, signatureAlgorithm);
  }

  /**
   * Perform the signature type specific processing of sign task data to produce the data to be signed.
   *
   * @param signatureTask requested signature task data
   * @param signerCertificate signer certificate
   * @param signatureAlgorithm signature algorithm
   * @return data to be signed
   * @throws SignatureException on error processing the requested signature task data
   */
  @Nonnull
  protected abstract TBSProcessingData processSignatureTypeTBSData(@Nonnull final RequestedSignatureTask signatureTask,
      @Nonnull final X509Certificate signerCertificate, @Nonnull final SignatureAlgorithm signatureAlgorithm)
      throws SignatureException;

  /** {@inheritDoc} */
  @Override
  public void checkSignTask(@Nonnull final RequestedSignatureTask signatureTask,
      @Nonnull final SignatureAlgorithm signatureAlgorithm) throws InvalidRequestException {

    // Note that on this level we consider absence of sign task and signature algorithm as a checked exception as it may
    // not be a programming error
    Optional.ofNullable(signatureTask).orElseThrow(() -> new InvalidRequestException("SignatureTask must not be null"));
    Optional.ofNullable(signatureAlgorithm)
        .orElseThrow(() -> new InvalidRequestException("SignatureAlgorithm must not be null"));
    Optional.ofNullable(signatureTask.getTbsData())
        .orElseThrow(() -> new InvalidRequestException("Null TBS data in sign request"));
    Optional.ofNullable(signatureTask.getSignatureType())
        .orElseThrow(() -> new InvalidRequestException("SignatureType must not be null"));
    final byte[] tbsData = Optional.ofNullable(signatureTask.getTbsData())
        .orElseThrow(() -> new InvalidRequestException("To be signed data must not be null"));
    final AdESType adESType = signatureTask.getAdESType();
    final boolean ades = adESType != null && (adESType.equals(AdESType.BES) || adESType.equals(AdESType.EPES));
    this.checkToBeSignedData(tbsData, ades, signatureTask.getAdESObject(), signatureAlgorithm);
  }

  /**
   * Perform signature type specific checks on the data to be signed input.
   *
   * @param tbsData data to be signed provided in the request
   * @param ades true if this is an AdES signature according to an ETSI AdES profile
   * @param adESObject optional AdES object provided in the request
   * @param signatureAlgorithm signature algorithm intended to be used to sign
   * @throws InvalidRequestException if the provided data is invalid
   */
  protected abstract void checkToBeSignedData(@Nonnull final byte[] tbsData, final boolean ades,
      @Nullable final AdESObject adESObject, @Nonnull final SignatureAlgorithm signatureAlgorithm)
      throws InvalidRequestException;

  /**
   * Gets the {@code strictProcessing} setting.
   *
   * @return the strict processing setting
   */
  protected boolean isStrictProcessing() {
    return this.strictProcessing;
  }

  /**
   * Gets the {@code includeIssuerSerial} setting.
   *
   * @return the includeIssuerSerial setting
   */
  protected boolean isIncludeIssuerSerial() {
    return this.includeIssuerSerial;
  }

  /**
   * Gets the supported processing rules.
   *
   * @return the supported processing rules
   */
  @Nonnull
  protected List<String> getSupportedProcessingRules() {
    return this.supportedProcessingRules;
  }

}
