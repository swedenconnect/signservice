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
import java.util.EmptyStackException;
import java.util.Stack;

import javax.annotation.Nonnull;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Default in memory RSA key provider.
 *
 * <p>
 * This key provider produces and holds a stock of pre-produced RSA keys. It is therefore important that this class is
 * instantiated as a singleton
 * </p>
 */
@Slf4j
public class StackedInMemoryRSAKeyProvider extends AbstractRSAKeyProvider {

  /**
   * The number of keys stored in this key stack.
   */
  private final int keyStackSize;

  /** The key stack holding stored keys. Note that the Stack is synchronized. */
  private final Stack<PkiCredential> keyStack;

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
    super(keySize);
    this.keyStackSize = keyStackSize;
    this.keyStack = new Stack<>();
    this.fillUpKeyStack();
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public PkiCredential getKeyPair() throws KeyException {
    final PkiCredential pkiCredential = this.getStackedKey();
    this.fillUpKeyStack();
    return pkiCredential;
  }

  /**
   * Gets a stacked key, or if not key pair is stacked, generates a new key pair.
   *
   * @return a PkiCredential
   * @throws KeyException for generation errors
   */
  @Nonnull
  private PkiCredential getStackedKey() throws KeyException {
    try {
      if (!this.keyStack.isEmpty()) {
        return this.keyStack.pop();
      }
    }
    catch (final EmptyStackException e) {
    }
    return this.generateKeyPair();
  }

  /**
   * Adds a newly generated key pair to the stack
   *
   * @param pkiCredential the credential to add
   */
  private void addStackedKey(@Nonnull final PkiCredential pkiCredential) {
    this.keyStack.push(pkiCredential);
  }

  /**
   * Get the current key stack size.
   *
   * @return the current key stack size
   */
  public int getCurrentStackSize() {
    return this.keyStack.size();
  }

  /**
   * Is called to start a thread filling up the key stack.
   */
  private void fillUpKeyStack() {
    if (this.keyGenerationThread != null && this.keyGenerationThread.isAlive()) {
      return;
    }
    this.keyGenerationThread = new Thread(new KeyBuilder());
    this.keyGenerationThread.start();
  }

  /**
   * Class implementing building of key pairs.
   */
  class KeyBuilder implements Runnable {

    /**
     * Generating RSA keys to fill the in memory stack to the set key stack size.
     */
    @Override
    public void run() {
      while (getCurrentStackSize() < keyStackSize) {
        final long startTime = System.currentTimeMillis();
        try {
          addStackedKey(generateKeyPair());
        }
        catch (final KeyException e) {
          log.error("Error creating RSA key", e);
          return;
        }
        final long keyGenTime = System.currentTimeMillis() - startTime;
        log.debug("Generated new RSA key with key size {} in {} ms. Keys in stack: {}",
            getKeySize(), keyGenTime, getCurrentStackSize());
      }
      log.debug("Completed RSA key generation to fill stack");
    }
  }

}
