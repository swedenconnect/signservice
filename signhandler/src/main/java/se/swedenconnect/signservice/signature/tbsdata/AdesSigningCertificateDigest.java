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
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Representation of the AdES digest of the signing certificate.
 */
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class AdesSigningCertificateDigest {

  /**
   * The URI for the digest method used to hash the signer certificate.
   *
   * @param digestMethod
   *          the URI for the digest method used to hash the signer certificate
   * @return the URI for the digest method used to hash the signer certificate
   */
  @Getter
  @Setter
  private String digestMethod;

  /**
   * The digest value.
   *
   * @param digestValue
   *          the digest value
   * @return the digest value
   */
  @Getter
  @Setter
  private byte[] digestValue;

}
