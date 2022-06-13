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
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.signature.AdESType;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.tbsdata.TBSDataProcessor;
import se.swedenconnect.signservice.signature.tbsdata.TBSProcessingData;

import javax.annotation.Nonnull;
import java.security.SignatureException;
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

  public AbstractTBSDataProcessor(List<String> supportedProcessingRules) {
    this.supportedProcessingRules = supportedProcessingRules;
  }

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

  protected void checkIndata(@Nonnull final RequestedSignatureTask signatureTask,
    @Nonnull final PkiCredential signingCredential,
    @Nonnull final SignatureAlgorithm signatureAlgorithm) throws SignatureException{
    Objects.requireNonNull(signatureTask, "SignatureTask must not be null");
    Objects.requireNonNull(signingCredential, "Signing credentials must not be null");
    Objects.requireNonNull(signatureAlgorithm, "Signature algorithm must not be null");
    Optional.ofNullable(signatureTask.getTbsData())
      .orElseThrow(() -> new SignatureException("Null TBS data in sign request"));
    Optional.ofNullable(signatureTask.getSignatureType())
      .orElseThrow(() -> new SignatureException("SignatureType must not be null"));
  }

}
