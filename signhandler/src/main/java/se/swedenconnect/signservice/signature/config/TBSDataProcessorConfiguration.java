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
package se.swedenconnect.signservice.signature.config;

import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import lombok.Getter;
import lombok.Setter;

/**
 * Configuration class for TBS data processors.
 */
public class TBSDataProcessorConfiguration {

  /** XML type. */
  public static final String XML_TYPE = "xml";

  /** PDF type. */
  public static final String PDF_TYPE = "pdf";

  /**
   * The type of processor.
   */
  @Getter
  @Setter
  @Nonnull
  private String type;

  /**
   * Defines if processing of input data is strict or applies the Postel's robustness principle. An example of this is
   * that a PAdES signature MUST NOT contain signing time in signed attributes. With strict processing a request with
   * signing time will fail. By default, such request will be accepted, but the signing time will be removed in line
   * with the PAdES standard.
   */
  @Getter
  @Setter
  private Boolean strictProcessing;

  /**
   * Defines if ESSCertID holding a hash of the signer certificate should include Issuer Serial data in addition to the
   * certificate hash. The default is {@code false}.
   */
  @Getter
  @Setter
  private Boolean includeIssuerSerial;

  /**
   * Supported processing rules URI:s.
   */
  @Getter
  @Setter
  @Nullable
  private List<String> supportedProcessingRules;

  /**
   * Relevant only if type is "xml". The default canonicalization algorithm to use. If not assigned,
   * {@code http://www.w3.org/2001/10/xml-exc-c14n#} is used.
   */
  @Getter
  @Setter
  @Nullable
  private String defaultCanonicalizationAlgorithm;

}
