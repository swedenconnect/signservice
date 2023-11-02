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
package se.swedenconnect.signservice.signature.tbsdata;

import lombok.Builder;
import se.swedenconnect.signservice.signature.AdESObject;

/**
 * Data class holding data related to a sign task that is the result of preparing data for signing.
 */
@Builder
public class TBSProcessingData {

  /** The data to be signed. */
  private byte[] tbsBytes;

  /** The ETSI advanced electronic signature data object (if applicable). */
  private AdESObject adesObject;

  /** The processing rules. */
  private String processingRules;

  /**
   * Default constructor.
   */
  public TBSProcessingData() {
  }

  /**
   * Constructor.
   *
   * @param tbsBytes the data to be signed
   * @param adesObject the ETSI advanced electronic signature data object
   * @param processingRules the processing rules
   */
  public TBSProcessingData(final byte[] tbsBytes, final AdESObject adesObject, final String processingRules) {
    super();
    this.tbsBytes = tbsBytes;
    this.adesObject = adesObject;
    this.processingRules = processingRules;
  }

  /**
   * Gets the data to be signed.
   *
   * @return data to be signed
   */
  public byte[] getTbsBytes() {
    return this.tbsBytes;
  }

  /**
   * Assigns the data to be signed.
   *
   * @param tbsBytes data to be signed
   */
  public void setTbsBytes(final byte[] tbsBytes) {
    this.tbsBytes = tbsBytes;
  }

  /**
   * Gets the ETSI advanced electronic signature data object (if applicable).
   *
   * @return ETSI advanced electronic signature data object (if applicable) or {@code null}
   */
  public AdESObject getAdesObject() {
    return this.adesObject;
  }

  /**
   * Assigns the ETSI advanced electronic signature data object.
   *
   * @param adesObject ETSI advanced electronic signature data object (if applicable)
   */
  public void setAdesObject(final AdESObject adesObject) {
    this.adesObject = adesObject;
  }

  /**
   * Gets the processing rules if set.
   *
   * @return data processing rules URI if set or {@code null}
   */
  public String getProcessingRules() {
    return this.processingRules;
  }

  /**
   * Assigns the processing rules.
   *
   * @param processingRules processing rules URI
   */
  public void setProcessingRules(final String processingRules) {
    this.processingRules = processingRules;
  }

}
