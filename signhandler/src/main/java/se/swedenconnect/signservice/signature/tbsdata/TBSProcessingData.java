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
package se.swedenconnect.signservice.signature.tbsdata;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.swedenconnect.signservice.signature.AdESObject;

/**
 * Data class holding data related to a sign task that is the result of preparing data for signing.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class TBSProcessingData {

  /**
   * The data to be signed
   *
   * @param tBSBytes data to be signed
   * @return data to be signed
   */
  private byte[] tBSBytes;

  /**
   * The ETSI advanced electronic signature data object (if applicable)
   *
   * @param tBSBytes ETSI advanced electronic signature data object (if applicable)
   * @return ETSI advanced electronic signature data object (if applicable) or null
   */
  private AdESObject adESObject;

  /**
   * The processing rules if set
   *
   * @param tBSBytes processing rules URI
   * @return data processing rules URI if set or null
   */
  private String processingRules;
}
