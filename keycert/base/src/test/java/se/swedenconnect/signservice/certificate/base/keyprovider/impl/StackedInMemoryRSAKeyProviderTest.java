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

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.certificate.base.utils.TestUtils;

import static org.junit.jupiter.api.Assertions.*;

/**
 * DefaultInMemoryRSAKeyProviderTests
 */
@Slf4j
class StackedInMemoryRSAKeyProviderTest {

  @Test
  void getKeyPair() throws Exception {
    int keySize = 2048;

    log.info("Default in memory RSA Key provider tests");
    StackedInMemoryRSAKeyProvider keyProvider = new StackedInMemoryRSAKeyProvider(keySize, 5);
    log.info("Created new key provider");
    assertEquals(5, keyProvider.getKeyStackSize());
    log.info("Confirmed key stack size");

    Thread keyGenerationThread = keyProvider.getKeyGenerationThread();
    log.info("keygen thread alive: {}", keyGenerationThread.isAlive());
    assertNotNull(keyGenerationThread);
    assertTrue(keyGenerationThread.isAlive());
    Thread.sleep(500);
    //Read 15 keys
    for (int i = 0; i < 7; i++) {
      long readStart = System.currentTimeMillis();
      assertNotNull(keyProvider.getKeyPair());
      long readTime = System.currentTimeMillis() - readStart;
      log.info("Reading key {} taking {} ms", i, readTime);
    }

    keyGenerationThread.join();
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