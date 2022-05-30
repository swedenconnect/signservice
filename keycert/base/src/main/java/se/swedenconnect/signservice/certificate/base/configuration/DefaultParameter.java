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
package se.swedenconnect.signservice.certificate.base.configuration;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Enumeration of default value parameters.
 */
@AllArgsConstructor
@Getter
public enum DefaultParameter {

  /**
   * Default value for the signature algorithm in the sign request.
   */
  signatureAlgorithm("signatureAlgorithm"),

  /**
   * Default certificate type.
   */
  certificateType("certificateTYpe"),

  /**
   * Default certificate profile.
   */
  certificateProfile("certificateProfile");

  /**
   * The identifier name of the parameter used to store and retrieve parameter values.
   *
   * @return the parameter name
   */
  private final String parameterName;

}
