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
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.certificate.base.keyprovider.KeyProvider;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.KeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Default in memory RSA key provider.
 *
 * <p>
 * This key provider produces and holds a stock of pre-produced RSA keys. It is therefore important that this
 * class is instantiated as a singleton
 * </p>
 */
@Slf4j
public class StackedInMemoryRSAKeyProvider implements KeyProvider {

  /**
   * The RSA key size served by this key provider.
   *
   * @return RSA key size served by this key provider
   */
  @Getter
  private final int keySize;

  /**
   * The number of keys stored in this key stack.
   *
   * @return the number of keys stored in this key stack
   */
  @Getter
  private final int keyStackSize;

  /** The key stack holding stored keys. */
  private final List<PkiCredential> keyStack;

  /**
   * The thread responsible for filling up the key stack in the background. The purpose of making it possible to get
   * this thread is to allow an external process to join with this thread to wait until the stack is filled up, or to
   * simply test if a current process to fill up the stack is in active.
   *
   * @return the key generation thread
   */
  @Getter
  private Thread keyGenerationThread;

  /**
   * Constructor.
   *
   * @param keySize key size
   * @param keyStackSize key stack size
   */
  public StackedInMemoryRSAKeyProvider(final int keySize, final int keyStackSize) {
    this.keySize = keySize;
    this.keyStackSize = keyStackSize;
    this.keyStack = new ArrayList<>();
    this.fillUpKeyStack();
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public synchronized PkiCredential getKeyPair() throws KeyException {
    final PkiCredential pkiCredential = Optional.ofNullable(this.addOrRetrieveStackedKey(null)).orElse(this.generateKeyPair());
    this.fillUpKeyStack();
    return pkiCredential;
  }

  /**
   * Add or remove a key from the key stack. This single synchronized function handles all changes to the key stack to
   * avoid conflicts.
   *
   * @param pkiCredential adds this key to the stack if this parameter is not null
   * @return A key pair if the stack was not empty and the provided key pair is null
   */
  @Nullable
  private synchronized PkiCredential addOrRetrieveStackedKey(@Nullable final PkiCredential pkiCredential) {

    if (pkiCredential == null) {
      // retrieve key
      if (this.keyStack.isEmpty()) {
        return null;
      }
      final PkiCredential keyPairFromStack = this.keyStack.get(0);
      this.keyStack.remove(0);
      return keyPairFromStack;
    }

    // Add key
    this.keyStack.add(pkiCredential);
    return null;

  }

  /**
   * Get the current key stack size.
   *
   * @return the current key stack size
   */
  public int getCurrentStackSize() {
    return this.keyStack.size();
  }

  private void fillUpKeyStack() {
    if (this.keyGenerationThread != null && this.keyGenerationThread.isAlive()) {
      return;
    }
    this.keyGenerationThread = new Thread(new KeyBuilder());
    this.keyGenerationThread.start();
  }

  private PkiCredential generateKeyPair() throws KeyException {
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

  class KeyBuilder implements Runnable {

    /**
     * Generating RSA keys to fill the in memory stack to the set key stack size.
     */
    @Override
    public void run() {
      while (StackedInMemoryRSAKeyProvider.this.keyStack.size() < StackedInMemoryRSAKeyProvider.this.keyStackSize) {
        final long startTime = System.currentTimeMillis();
        try {
          StackedInMemoryRSAKeyProvider.this
              .addOrRetrieveStackedKey(StackedInMemoryRSAKeyProvider.this.generateKeyPair());
        }
        catch (final KeyException e) {
          log.error("Error creating RSA key", e);
          return;
        }
        final long keyGenTime = System.currentTimeMillis() - startTime;
        log.debug("Generated new RSA key with key size {} in {} ms. Keys in stack: {}",
            StackedInMemoryRSAKeyProvider.this.keySize, keyGenTime,
            StackedInMemoryRSAKeyProvider.this.keyStack.size());
      }
      log.debug("Completed RSA key generation at stick size {}", StackedInMemoryRSAKeyProvider.this.keyStackSize);
    }
  }

}
