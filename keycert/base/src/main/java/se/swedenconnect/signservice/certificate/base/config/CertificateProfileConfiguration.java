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

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Configuration data for a certificate profile.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CertificateProfileConfiguration {

  /**
   * List of certificate policy object identifier values.
   */
  private List<String> policies;

  /**
   * Criticality for certificate policies extension. The default is {@code false}.
   */
  @Builder.Default
  private boolean policiesCritical = false;

  /**
   * List of extended key usage object identifier values.
   */
  private List<String> extendedKeyUsages;

  /**
   * Criticality of extended key usage extension. The default is {@code false}.
   */
  @Builder.Default
  private boolean extendedKeyUsageCritical = false;

  /**
   * Optional settings for certificate key usage.
   */
  private SigningKeyUsageDirective usageDirective;

  /**
   * Criticality of key usage extension. The default is {@code true}.
   */
  @Builder.Default
  private boolean keyUsageCritical = true;

  /**
   * Criticality of basic constraints extension.
   */
  @Builder.Default
  private boolean basicConstraintsCritical = false;

}
