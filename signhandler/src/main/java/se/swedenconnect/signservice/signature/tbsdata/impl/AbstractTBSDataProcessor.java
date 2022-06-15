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
package se.swedenconnect.signservice.signature.tbsdata.impl;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.signature.AdESObject;
import se.swedenconnect.signservice.signature.AdESType;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;
import se.swedenconnect.signservice.signature.tbsdata.TBSDataProcessor;
import se.swedenconnect.signservice.signature.tbsdata.TBSProcessingData;

import javax.annotation.Nonnull;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Abstract implementation of TBS data processor
 */
@Slf4j
public abstract class AbstractTBSDataProcessor implements TBSDataProcessor {

  /**
   * Defines if processing of input data is strict or applies the Postel's robustness principle.
   * An example of this is that a PAdES signature MUST NOT contain signing time in signed attributes.
   * With strict processing a request with signing time will fail. By default, such request
   * will be accepted, but the signing time will be removed in line with the PAdES standard.
   *
   * @param strictProcessing true to strictly fail all non-conformance requests
   */
  @Setter protected boolean strictProcessing = false;

  /**
   * Defines if ESSCertID holding a hash of the signer certificate should include Issuer Serial
   * data in addition to the certificate hash
   *
   * @param includeIssuerSerial true to include issuer serial data
   */
  @Setter protected boolean includeIssuerSerial = false;

  /** Supported processing rules */
  protected final List<String> supportedProcessingRules;

  /**
   * Constructor
   *
   * @param supportedProcessingRules list of processing rule identifiers supported by this TBS data processor
   */
  public AbstractTBSDataProcessor(List<String> supportedProcessingRules) {
    this.supportedProcessingRules = supportedProcessingRules;
  }

  /**
   * Check processing rules of this TBS data processor against requested processing rule
   *
   * @param processingRulesUri requested processing rule
   * @throws SignatureException on error processing according to the required processing rule
   */
  protected void defaultProcessingRuleCheck(String processingRulesUri) throws SignatureException {
    if (processingRulesUri == null && this.supportedProcessingRules.isEmpty()) {
      log.debug("Using default processing rules");
    }
    else {
      if (processingRulesUri != null) {
        if (this.supportedProcessingRules.contains(processingRulesUri)) {
          log.debug("Using supported processing rule: {}", processingRulesUri);
        }
        else {
          throw new SignatureException(
            "Processing rule " + processingRulesUri + " is not supported." +
              " Expected one of: " + String.join(",", this.supportedProcessingRules));
        }
      }
      else {
        log.debug("Null requested processing rule is accepted among supported processing rules. {}",
          String.join(",", this.supportedProcessingRules));
      }
    }
  }

  @Override public TBSProcessingData processSignTaskData(@Nonnull final RequestedSignatureTask signatureTask,
    @Nonnull final X509Certificate signerCertificate, @Nonnull final SignatureAlgorithm signatureAlgorithm)
    throws SignatureException {
    // Note that on this level absence of any input parameter is considered a programming error and produces
    // an unchecked NullPointerException
    Objects.requireNonNull(signatureTask, "SignatureTask must not be null");
    Objects.requireNonNull(signerCertificate, "Signer certificate must not be null");
    Objects.requireNonNull(signatureAlgorithm, "Signature algorithm must not be null");

    try {
      // Validate the input data
      checkSignTask(signatureTask, signatureAlgorithm);
    }
    catch (InvalidRequestException e) {
      // Convert invalid request to SignatureException
      throw new SignatureException(e.getMessage());
    }

    return processSignatureTypeTBSData(signatureTask, signerCertificate, signatureAlgorithm);
  }

  /**
   * Perform the signature type specific processing of sign task data to produce the data to be signed
   *
   * @param signatureTask requested signature task data
   * @param signerCertificate signer certificate
   * @param signatureAlgorithm signature algorithm
   * @return data to be signed
   * @throws SignatureException on error processing the requested signature task data
   */
  protected abstract TBSProcessingData processSignatureTypeTBSData(RequestedSignatureTask signatureTask,
    X509Certificate signerCertificate, SignatureAlgorithm signatureAlgorithm) throws SignatureException;

  @Override public void checkSignTask(final RequestedSignatureTask signatureTask,
    final SignatureAlgorithm signatureAlgorithm) throws InvalidRequestException {
    // Note that on this level we consider absence of sign task and signature algorithm as a checked exception as it may not be a programming error
    Optional.ofNullable(signatureTask).orElseThrow(() -> new InvalidRequestException("SignatureTask must not be null"));
    Optional.ofNullable(signatureAlgorithm)
      .orElseThrow(() -> new InvalidRequestException("SignatureAlgorithm must not be null"));
    Optional.ofNullable(signatureTask.getTbsData())
      .orElseThrow(() -> new InvalidRequestException("Null TBS data in sign request"));
    Optional.ofNullable(signatureTask.getSignatureType())
      .orElseThrow(() -> new InvalidRequestException("SignatureType must not be null"));
    byte[] tbsData = Optional.ofNullable(signatureTask.getTbsData())
      .orElseThrow(() -> new InvalidRequestException("To be signed data must not be null"));
    AdESType adESType = signatureTask.getAdESType();
    boolean ades = adESType != null && (adESType.equals(AdESType.BES) || adESType.equals(AdESType.EPES));
    checkToBeSignedData(tbsData, ades, signatureTask.getAdESObject(), signatureAlgorithm);
  }

  /**
   * Perform signature type specific checks on the data to be signed input
   * @param tbsData data to be signed provided in the request
   * @param ades true if this is an AdES signature according to an ETSI AdES profile
   * @param adESObject optional AdES object provided in the request
   * @param signatureAlgorithm signature algorithm intended to be used to sign
   * @throws InvalidRequestException if the provided data is invalid
   */
  protected abstract void checkToBeSignedData(byte[] tbsData, boolean ades, AdESObject adESObject,
    SignatureAlgorithm signatureAlgorithm) throws InvalidRequestException;
}
