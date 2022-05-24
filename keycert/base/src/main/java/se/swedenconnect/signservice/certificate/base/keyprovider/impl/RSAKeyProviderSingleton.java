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

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.signature.XMLSignature;
import se.swedenconnect.signservice.certificate.base.keyprovider.KeyProvider;

/**
 * This class provides a RSAKeyProviderSingleton.
 *
 * The reason why you may want the RSA key provider as a singleton is that you want the
 * RSA key provider to carry a stack of pre-produced RSA keys. This is much more efficient if
 * all processes use the same instance of the RSA key provider.
 */
@Slf4j
public class RSAKeyProviderSingleton {

  /** private constructor */
  private RSAKeyProviderSingleton() {
  }

  /** The singleton instance of the RSA key provider */
  private static volatile KeyProvider instance = null;

  /**
   * Gets the singleton instance of the RSA key provider
   * @return RSA key provider singleton
   */
  public static KeyProvider getSingletonInstance() {
    if (instance == null) {
      log.info("No RSA key provider singleton instance is set. Setting default in memory key provider with key size 3072 and stack size 100");
      setInstance(new DefaultInMemoryRSAKeyProvider(3072, 100));
    }
    return instance;
  }

  /**
   * Set a new singleton instance to be returned by this singleton provider
   * @param rsaKeyProvider
   */
  public static synchronized void setInstance(@NonNull final KeyProvider rsaKeyProvider) {
    instance = rsaKeyProvider;
    log.info("Setting RSA key provider rsaKeyProvider of class {}", rsaKeyProvider.getClass().getName());
  }
}
