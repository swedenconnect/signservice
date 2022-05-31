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

import lombok.Getter;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.certificate.base.keyprovider.KeyProvider;

import javax.annotation.Nonnull;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * RSA key provider generating RSA keys on demand. This differs from the stacked RSA key
 * provider that pre-generates RSA keys in a background thread to optimize the time
 * it takes to obtain a key.
 */
public class OnDemandInMemoryRSAkeyProvider implements KeyProvider {

  /**
   * The RSA key size served by this key provider.
   *
   * @return RSA key size served by this key provider
   */
  @Getter
  private final int keySize;

  /**
   * Constructor for the on-demand RSA key provider.
   *
   * @param keySize key size for generated RSA keys
   */
  public OnDemandInMemoryRSAkeyProvider(final int keySize) {
    this.keySize = keySize;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public PkiCredential getKeyPair() throws KeyException {
    try {
      KeyPairGenerator generator;
      generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(this.keySize);
      KeyPair keyPair = generator.generateKeyPair();
      return new BasicCredential(keyPair.getPublic(), keyPair.getPrivate());
    }
    catch (final NoSuchAlgorithmException e) {
      throw new KeyException("Error generating RSA key pair", e);
    }
  }
}
