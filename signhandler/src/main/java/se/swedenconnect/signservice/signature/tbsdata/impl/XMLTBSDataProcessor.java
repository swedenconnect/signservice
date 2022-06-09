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
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class XMLTBSDataProcessor implements TBSDataProcessor {

  /** Supported processing rules */
  private final List<String> supportedProcessingRules;

  /**
   * Constructor that allows setting of supported processing rules
   *
   * @param supportedProcessingRules list of supported processing rules for this TBS data processor
   */
  public XMLTBSDataProcessor(List<String> supportedProcessingRules) {
    this.supportedProcessingRules = supportedProcessingRules;
  }

  /**
   * Constructor for this XML TBS data processor with default settings
   */
  public XMLTBSDataProcessor() {
    this.supportedProcessingRules = Collections.EMPTY_LIST;
  }

  @Override public TBSProcessingData getTBSData(@Nonnull final RequestedSignatureTask signatureTask,
    @Nonnull final PkiCredential signingCredential,
    @Nonnull final SignatureAlgorithm signatureAlgorithm) throws SignatureException {

    Objects.requireNonNull(signatureTask, "SignatureTask must not be null");
    Objects.requireNonNull(signingCredential, "Signing credentials must not be null");
    Objects.requireNonNull(signatureAlgorithm, "Signature algorithm must not be null");
    byte[] tbsBytes = Optional.ofNullable(signatureTask.getTbsData())
      .orElseThrow(() -> new SignatureException("Null data to be sign in sign request"));
    SignatureType signatureType = Optional.ofNullable(signatureTask.getSignatureType())
      .orElseThrow(() -> new SecurityException("SignatureType must not be null"));
    if (!signatureType.equals(SignatureType.PDF)) {
      throw new SignatureException("Signature type must be PDF");
    }
    AdESType adESType = signatureTask.getAdESType();

    if (signatureTask.getProcessingRulesUri() == null && this.supportedProcessingRules.isEmpty()) {
      log.debug("Using default processing rules");
    }
    else {
      if (signatureTask.getProcessingRulesUri() != null) {
        if (this.supportedProcessingRules.contains(signatureTask.getProcessingRulesUri())) {
          log.debug("Using supported processing rule: {}", signatureTask.getProcessingRulesUri());
        }
        else {
          throw new SignatureException(
            "Processing rule " + signatureTask.getProcessingRulesUri() + " is not supported." +
              " Expected one of: " + String.join(",", this.supportedProcessingRules));
        }
      }
      else {
        log.debug("Null requested processing rule is accepted among supported processing rules. {}",
          String.join(",", this.supportedProcessingRules));
      }
    }

    boolean xades = AdESType.BES.equals(adESType) || AdESType.EPES.equals(adESType);
    log.debug("XAdES signature = {}", xades);
    return null;

  }
}
