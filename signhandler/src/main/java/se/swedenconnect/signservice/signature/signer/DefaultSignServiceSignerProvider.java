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
package se.swedenconnect.signservice.signature.signer;

import java.util.Objects;

import jakarta.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.algorithms.Algorithm;
import se.swedenconnect.security.algorithms.AlgorithmRegistry;
import se.swedenconnect.security.algorithms.RSAPSSSignatureAlgorithm;
import se.swedenconnect.security.algorithms.SignatureAlgorithm;
import se.swedenconnect.signservice.signature.SignatureType;

/**
 * Default implementation of the signer provider
 */
@Slf4j
public class DefaultSignServiceSignerProvider implements SignServiceSignerProvider {

  /** The algorithm registry used to get information about supported algorithms */
  private final AlgorithmRegistry algorithmRegistry;

  /**
   * Constructor
   *
   * @param algorithmRegistry the algorithm registry used to get information about supported algorithms
   */
  public DefaultSignServiceSignerProvider(final AlgorithmRegistry algorithmRegistry) {
    this.algorithmRegistry = algorithmRegistry;
  }

  /** {@inheritDoc} */
  @Override public SignServiceSigner getSigner(@Nonnull final String signatureAlgorithm,
    @Nonnull final SignatureType signatureType) {

    Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm must not be null");
    Objects.requireNonNull(signatureType, "signatureType must not be null");

    final Algorithm algorithm = algorithmRegistry.getAlgorithm(signatureAlgorithm);
    if (algorithm == null) {
      throw new IllegalArgumentException("Algorithm " + signatureAlgorithm + " is not supported");
    }
    if (!(algorithm instanceof SignatureAlgorithm)) {
      throw new IllegalArgumentException("Non signature algorithm specified: " + signatureAlgorithm);
    }

    final SignatureAlgorithm sigAlgo = (SignatureAlgorithm) algorithm;
    if (sigAlgo instanceof RSAPSSSignatureAlgorithm) {
      return new SignServiceRSAPSSSigner();
    }

    if (sigAlgo.getKeyType().equalsIgnoreCase("EC")) {
      return new SignServiceECSigner(signatureType);
    }

    if (sigAlgo.getKeyType().equalsIgnoreCase("RSA")) {
      return new SignServiceRSASigner();
    }

    log.debug("Unsupported algorithm {}. This algorithm does not have a suitable signer", signatureAlgorithm);

    throw new IllegalArgumentException("No suitable signer exists for algorithm: " + signatureAlgorithm);
  }
}
