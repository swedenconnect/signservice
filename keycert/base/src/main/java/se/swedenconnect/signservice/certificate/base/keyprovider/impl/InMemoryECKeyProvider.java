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

import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.certificate.base.keyprovider.KeyProvider;

import javax.annotation.Nonnull;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Objects;

/**
 * Default in memory Elliptic Curve key provider.
 */
public class InMemoryECKeyProvider implements KeyProvider {

  /** Parameter specification for the EC keys to generate */
  private final ECGenParameterSpec ecSpec;

  /**
   * Constructor for the EC key provider.
   *
   * @param ecSpec parameter specification for EC keys to generate
   */
  public InMemoryECKeyProvider(@Nonnull final ECGenParameterSpec ecSpec) {
    this.ecSpec = Objects.requireNonNull(ecSpec, "ecSpec must not be null");
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public PkiCredential getKeyPair() throws KeyException {
    try {
      final KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA");
      g.initialize(this.ecSpec, new SecureRandom());
      KeyPair keyPair = g.generateKeyPair();
      return new BasicCredential(keyPair.getPublic(), keyPair.getPrivate());
    }
    catch (final InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
      throw new KeyException("Error generating EC key", e);
    }
  }
}
