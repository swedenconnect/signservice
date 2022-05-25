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
import se.swedenconnect.signservice.certificate.base.keyprovider.KeyProvider;

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
 * This key provider produces and holds a stock of pre produced RSA keys.
 * </p>
 */
@Slf4j
public class DefaultInMemoryRSAKeyProvider implements KeyProvider {

  /** @return RSA key size served by this key provider */
  @Getter private final int keySize;

  /** @return the number of keys stored in this key stack */
  @Getter private final int keyStackSize;

  /** The key stack holding stored keys */
  private List<KeyPair> keyStack;

  /**
   * The thread responsible for filling up the key stack in the background. The purpose of making it possible
   * to get this thread is to allow an external process to join with this thread to wait until the stack is
   * filled up, or to simply test if a current process to fill up the stack is in active.
   *
   * @return the key generation thread
   */
  @Getter private Thread keyGenerationThread;

  /**
   * Constructor
   *
   * @param keySize key size
   * @param keyStackSize key stack size
   */
  public DefaultInMemoryRSAKeyProvider(int keySize, int keyStackSize) {
    this.keySize = keySize;
    this.keyStackSize = keyStackSize;
    keyStack = new ArrayList<>();
    fillUpKeyStack();
  }

  /** {@inheritDoc} */
  @Override
  public synchronized KeyPair getKeyPair() throws KeyException {
    KeyPair keyPair = Optional.ofNullable(addOrRetrieveStackedKey(null)).orElse(generateKeyPair());
    fillUpKeyStack();
    return keyPair;
  }

  /**
   * Add or remove a key from the key stack. This single synchronized function handles all changes to the key stack
   * to avoid conflicts.
   *
   * @param keyPair adds this key to the stack if this parameter is not null
   * @return A key pair if the stack was not empty and the provided key pair is null
   */
  private synchronized KeyPair addOrRetrieveStackedKey(@Nullable KeyPair keyPair) {

    if (keyPair == null) {
      // retrieve key
      if (keyStack.isEmpty()) {
        return null;
      }
      KeyPair keyPairFromStack = keyStack.get(0);
      keyStack.remove(0);
      return keyPairFromStack;
    }

    // Add key
    keyStack.add(keyPair);
    return null;

  }

  /**
   * Get the current key stack size
   *
   * @return the current key stack size
   */
  public int getCurrentStackSize() {
    return keyStack.size();
  }

  private void fillUpKeyStack() {
    if (keyGenerationThread != null && keyGenerationThread.isAlive()) {
      return;
    }
    keyGenerationThread = new Thread(new KeyBuilder());
    keyGenerationThread.start();
  }

  private KeyPair generateKeyPair() throws KeyException {
    try {
      KeyPairGenerator generator;
      generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(keySize);
      return generator.generateKeyPair();
    }
    catch (NoSuchAlgorithmException e) {
      throw new KeyException("Error generating RSA key pair", e);
    }
  }

  class KeyBuilder implements Runnable {

    /**
     * Generating RSA keys to fill the in memory stack to the set key stack size
     */
    @Override public void run() {
      while (keyStack.size() < keyStackSize) {
        long startTime = System.currentTimeMillis();
        try {
          addOrRetrieveStackedKey(generateKeyPair());
        }
        catch (KeyException e) {
          log.error("Error creating RSA key", e);
          return;
        }
        long keyGenTime = System.currentTimeMillis() - startTime;
        log.debug("Generated new RSA key with key size {} in {} ms. Keys in stack: {}", keySize, keyGenTime,
          keyStack.size());
      }
      log.debug("Completed RSA key generation at stick size {}", keyStackSize);
    }
  }

}
