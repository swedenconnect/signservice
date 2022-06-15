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
import se.swedenconnect.signservice.signature.SignatureType;
import se.swedenconnect.signservice.signature.tbsdata.TBSDataProcessor;
import se.swedenconnect.signservice.signature.tbsdata.TBSDataProcessorProvider;

import javax.annotation.Nonnull;
import java.security.SignatureException;
import java.util.Objects;

/**
 * Default provider of a suitable processor to prepare data to be signed
 */
@Slf4j
public class DefaultTBSDataProcessorProvider implements TBSDataProcessorProvider {

  /** XML TBS data processor */
  private final TBSDataProcessor xmlTBSDataProcessor;

  /** PDF TBS data processor */
  private final TBSDataProcessor pdfTBSDataProcessor;

  /**
   * Default constructor
   */
  public DefaultTBSDataProcessorProvider() {
    xmlTBSDataProcessor = new XMLTBSDataProcessor();
    pdfTBSDataProcessor = new PDFTBSDataProcessor();
  }

  /**
   * Constructor providing explicit XML and PDF TBS data processors
   *
   * @param xmlTBSDataProcessor XML TBS data processor
   * @param pdfTBSDataProcessor PDF TBS data processor
   */
  public DefaultTBSDataProcessorProvider(
    TBSDataProcessor xmlTBSDataProcessor,
    TBSDataProcessor pdfTBSDataProcessor) {
    this.xmlTBSDataProcessor = xmlTBSDataProcessor;
    this.pdfTBSDataProcessor = pdfTBSDataProcessor;
  }

  /** {@inheritDoc} */
  @Override public TBSDataProcessor getTBSDataProcessor(@Nonnull final SignatureType signatureType) throws SignatureException {

    log.debug("Requesting TBS data processor for signature type {}", signatureType);
    Objects.requireNonNull(signatureType, "SignatureType must not be null");

    switch (signatureType) {
    case XML:
      return xmlTBSDataProcessor;
    case PDF:
      return pdfTBSDataProcessor;
    default:
      log.debug("Unsupported signature type: {}", signatureType);
      throw new SignatureException("Signature type " + signatureType + " is not supported");
    }
  }
}
