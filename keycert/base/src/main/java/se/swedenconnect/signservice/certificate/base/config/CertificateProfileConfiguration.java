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
package se.swedenconnect.signservice.certificate.base.config;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.Collections;
import java.util.List;

/**
 * Configuration data for a certificate profile
 */
@Data
@AllArgsConstructor
@Builder
public class CertificateProfileConfiguration {

  /** List of certificate policy object identifier values */
  private List<String> policy;
  /** Criticality for certificate policies extension */
  private Boolean policyCritical;
  /** List of extended key usage object identifier values */
  private List<String> extendedKeyUsages;
  /** Criticality of extended key usage extension */
  private Boolean extendedKeyUsageCritical;
  /** Optional settings for certificate key usage */
  private List<OptionalUsageEnum> usageType;
  /** Criticality of key usage extension */
  private Boolean keyUsageCritical;
  /** Criticality of basic constraints extension */
  private Boolean basicConstraintsCritical;

  /**
   * Get instance of default certificate profile configuration data for sign services
   *
   * @return default certificate profile configuration
   */
  public static CertificateProfileConfiguration getDefaultConfiguration() {
    return getBuilderWithDefaultValues().build();
  }

  /**
   * Get instance of certificate profile configuration data builder for sign services with default values
   *
   * @return certificate profile configuration data builder with default values
   */
  public static CertificateProfileConfigurationBuilder getBuilderWithDefaultValues(){
    return CertificateProfileConfiguration.builder()
      .policy(Collections.emptyList())
      .policyCritical(false)
      .extendedKeyUsages(Collections.emptyList())
      .extendedKeyUsageCritical(false)
      .usageType(Collections.emptyList())
      .keyUsageCritical(true)
      .basicConstraintsCritical(false);
  }


}

