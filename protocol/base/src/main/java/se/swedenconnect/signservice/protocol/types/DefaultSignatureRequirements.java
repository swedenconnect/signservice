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
package se.swedenconnect.signservice.protocol.types;

import java.util.Objects;

import se.swedenconnect.signservice.api.protocol.types.SignatureRequirements;

/**
 * Default implementation of the {@link SignatureRequirements} interface.
 */
public class DefaultSignatureRequirements implements SignatureRequirements {

  /** For serializing. */
  private static final long serialVersionUID = 4588737868274206909L;

  /** The requested signature algorithm. */
  private final String signatureAlgorithm;

  /**
   * Constructor.
   *
   * @param signatureAlgorithm the requested signature algorithm
   */
  public DefaultSignatureRequirements(final String signatureAlgorithm) {
    this.signatureAlgorithm = signatureAlgorithm;
  }

  /** {@inheritDoc} */
  @Override
  public String getSignatureAlgorithm() {
    return this.signatureAlgorithm;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.signatureAlgorithm);
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof DefaultSignatureRequirements)) {
      return false;
    }
    final DefaultSignatureRequirements other = (DefaultSignatureRequirements) obj;
    return Objects.equals(this.signatureAlgorithm, other.signatureAlgorithm);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("signature-algorithm='%s'", this.signatureAlgorithm);
  }

}
