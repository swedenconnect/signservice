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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.certificate.base.utils.TestUtils;

/**
 * DefaultInMemoryRSAKeyProviderTests
 */
@Slf4j
class StackedInMemoryRSAKeyProviderTest {

  @Test
  void getKeyPair() throws Exception {
    int keySize = 2048;

    log.info("Default in memory RSA Key provider tests");
    final int stackSize = 5;
    StackedInMemoryRSAKeyProvider keyProvider = new StackedInMemoryRSAKeyProvider(keySize, stackSize);
    log.info("Created new key provider");

    Thread keyGenerationThread = keyProvider.getKeyGenerationThread();
    log.info("keygen thread alive: {}", keyGenerationThread.isAlive());
    assertNotNull(keyGenerationThread);
    assertTrue(keyGenerationThread.isAlive());
    Thread.sleep(500);
    // Read 15 keys
    for (int i = 0; i < 7; i++) {
      long readStart = System.currentTimeMillis();
      assertNotNull(keyProvider.getKeyPair());
      long readTime = System.currentTimeMillis() - readStart;
      log.info("Reading key {} taking {} ms", i, readTime);
    }

    // Wait until keys has filled up
    log.info("Waiting for keys to fill up in stack...");
    long startWait = System.currentTimeMillis();
    long maxWaitTime = startWait + 10000L;
    while (keyProvider.getCurrentStackSize() < stackSize && System.currentTimeMillis() < maxWaitTime) {
      Thread.sleep(100);
    }
    log.info("Wait completed in {} ms with {} keys out of {} in stack", System.currentTimeMillis() - startWait,
        keyProvider.getCurrentStackSize(), stackSize);

    assertEquals(keySize, keyProvider.getKeySize());
    assertEquals(5, keyProvider.getCurrentStackSize());

    assertFalse(keyGenerationThread.isAlive());

    log.info("Reading 2 keys from full stack");
    PkiCredential keyPair1 = keyProvider.getKeyPair();
    PkiCredential keyPair2 = keyProvider.getKeyPair();

    log.info("Got key1 from RSA key provider\n" + TestUtils.base64Print(keyPair1.getPublicKey().getEncoded(), 80));
    log.info("Got key2 from RSA key provider\n" + TestUtils.base64Print(keyPair2.getPublicKey().getEncoded(), 80));

    assertNotEquals(keyPair1.getPublicKey(), keyPair2.getPublicKey());

    log.info("Wait for key generation thread to become alive. Is alive = {}", keyGenerationThread.isAlive());
    // Wait to see if the keyGeneration thread becomes alive
    long startTime = System.currentTimeMillis();
    while (System.currentTimeMillis() < (startTime + 2000) && !keyGenerationThread.isAlive()) {
      Thread.sleep(100);
    }
  }

}
