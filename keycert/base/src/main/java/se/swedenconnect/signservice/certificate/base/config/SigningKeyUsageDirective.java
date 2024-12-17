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
package se.swedenconnect.signservice.certificate.base.config;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Directive when configuring signing keys. Signing keys are given the key usages for signing by default, including
 * non-repudiation. Using this directive it is also possible to mark that the key should be used for encryption, and
 * to disable the non-repudiation usage.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SigningKeyUsageDirective {

  /**
   * Flag that marks the key usage for the signing key for encryption (as well as signing).
   */
  @Builder.Default
  private boolean encrypt = false;

  /**
   * Flag that marks that the key usage for the signing key should not include non-repudiation.
   */
  @Builder.Default
  private boolean excludeNonRepudiation = false;

}
