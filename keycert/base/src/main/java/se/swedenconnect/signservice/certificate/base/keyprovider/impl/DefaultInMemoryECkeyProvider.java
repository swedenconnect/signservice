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

package se.swedenconnect.signservice.certificate.base.keyprovider.impl;

import se.swedenconnect.signservice.certificate.base.keyprovider.KeyProvider;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * Default in memory Elliptic Curve key provider
 */
public class DefaultInMemoryECkeyProvider implements KeyProvider {

  /** Parameter specification for the EC keys to generate */
  private final ECGenParameterSpec ecSpec;

  /**
   * Constructor for the EC key provider.
   *
   * @param ecSpec parameter specification for EC keys to generate
   */
  public DefaultInMemoryECkeyProvider(ECGenParameterSpec ecSpec) {
    this.ecSpec = ecSpec;
  }

  /** {@inheritDoc} */
  @Override public KeyPair getKeyPair() throws KeyException {
    try {
      KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
      g.initialize(ecSpec, new SecureRandom());
      return g.generateKeyPair();
    }
    catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
      throw new KeyException("Error generating EC key", e);
    }
  }
}
