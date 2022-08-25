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
package se.swedenconnect.signservice.certificate.keyprovider;

import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.annotation.Nonnull;

import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Abstract base class for RSA key providers.
 */
public abstract class AbstractRSAKeyProvider implements KeyProvider {

  /** The RSA key size served by this key provider. */
  private final int keySize;

  /**
   * Constructor.
   *
   * @param keySize the key size (in bits) for generated keys
   */
  public AbstractRSAKeyProvider(final int keySize) {
    this.keySize = keySize;
  }

  /** {@inheritDoc} */
  @Override
  public boolean supports(@Nonnull final String keyType) {
    return "RSA".equalsIgnoreCase(keyType);
  }

  /**
   * Generates an RSA key pair.
   *
   * @return a PkiCredential
   * @throws KeyException for generation errors
   */
  protected PkiCredential generateKeyPair() throws KeyException {
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

  /**
   * Gets the key size.
   *
   * @return the key size
   */
  protected int getKeySize() {
    return this.keySize;
  }

}
