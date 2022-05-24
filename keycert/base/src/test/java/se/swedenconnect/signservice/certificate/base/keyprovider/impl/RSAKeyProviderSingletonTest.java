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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.swedenconnect.signservice.certificate.base.keyprovider.KeyProvider;

import java.security.KeyException;
import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

/**
 * RSAKeyProviderSingletonTests
 */
class RSAKeyProviderSingletonTest {

  public static KeyProvider defaultKeyProvider;

  @BeforeAll
  public static void init(){
    defaultKeyProvider = RSAKeyProviderSingleton.getSingletonInstance();
  }

  @Test
  void testGetInstance() throws Exception {
    // Get the key provider from the same source
    KeyProvider rsaKeyProvider = RSAKeyProviderSingleton.getSingletonInstance();
    assertEquals(defaultKeyProvider.getClass(), rsaKeyProvider.getClass());
    RSAKeyProviderSingleton.setInstance(new DummyRSAKeyProvider());
    assertEquals(DummyRSAKeyProvider.class , RSAKeyProviderSingleton.getSingletonInstance().getClass());
    assertThrows(NullPointerException.class, () -> RSAKeyProviderSingleton.setInstance(null));
    RSAKeyProviderSingleton.setInstance(new DefaultInMemoryRSAKeyProvider(3072, 100));
    assertEquals(defaultKeyProvider.getClass(), RSAKeyProviderSingleton.getSingletonInstance().getClass());
  }

  class DummyRSAKeyProvider implements KeyProvider{

    @Override public KeyPair getKeyPair() throws KeyException {
      return null;
    }
  }

}