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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.certificate.base.keyprovider.KeyProvider;
import se.swedenconnect.signservice.certificate.base.utils.TestUtils;

/**
 * Test for on demand RSA key generator
 */
@Slf4j
class OnDemandInMemoryRSAKeyProviderTest {

  @Test
  void getKeyPair() throws Exception {
    log.info("Testing on-demand key provider -  size 2048 keys");
    KeyProvider keyProvider = new OnDemandInMemoryRSAKeyProvider(2048);
    PkiCredential keyPair = keyProvider.getKeyPair();
    assertNotNull(keyPair);
    assertNotNull(keyPair.getPrivateKey());
    assertNotNull(keyPair.getPublicKey());
    assertTrue(keyPair.getPublicKey() instanceof RSAPublicKey);
    assertEquals(((RSAPublicKey)keyPair.getPublicKey()).getModulus().bitLength(), 2048);
    log.info("Generated key pair with private key:\n{}", TestUtils.base64Print(keyPair.getPrivateKey().getEncoded(), 80));
    log.info("Generated key pair with public key:\n{}", TestUtils.base64Print(keyPair.getPublicKey().getEncoded(), 80));
  }

}