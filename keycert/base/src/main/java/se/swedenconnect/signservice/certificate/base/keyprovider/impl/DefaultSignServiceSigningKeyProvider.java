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
import se.swedenconnect.signservice.certificate.base.keyprovider.KeyProvider;
import se.swedenconnect.signservice.certificate.base.keyprovider.SignServiceSigningKeyProvider;
import se.swedenconnect.signservice.session.SignServiceContext;

import java.security.KeyException;
import java.security.KeyPair;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

/**
 * Implementation of a default key provider
 */
public class DefaultSignServiceSigningKeyProvider implements SignServiceSigningKeyProvider {

  private final KeyProvider rsaKeyProvider;
  private final KeyProvider ecKeyProvider;

  /**
   * Constructor for a default sign service key provider using the following preset parameters:
   *
   * <ul>
   *   <li>RSA key length 3072 bits</li>
   *   <li>RSA pre-produced key stack size = 100 keys</li>
   *   <li>EC curve NIST P-256</li>
   * </ul>
   */
  public DefaultSignServiceSigningKeyProvider() {
    RSAKeyProviderSingleton.setInstance(new DefaultInMemoryRSAKeyProvider(3072, 100));
    rsaKeyProvider = RSAKeyProviderSingleton.getSingletonInstance();
    ecKeyProvider = new DefaultInMemoryECkeyProvider(new ECGenParameterSpec("P-256"));
  }

  /**
   * Constructor for default key provider
   *
   * @param rsaKeyLen key size of the generated RSA keys
   * @param rsaStackSize number of pre-produced RSA keys kept in the key generator
   * @param ecParameterSpec the EC curve to use for generating EC keys
   */
  public DefaultSignServiceSigningKeyProvider(int rsaKeyLen, int rsaStackSize, ECGenParameterSpec ecParameterSpec) {
    RSAKeyProviderSingleton.setInstance(new DefaultInMemoryRSAKeyProvider(rsaKeyLen, rsaStackSize));
    rsaKeyProvider = RSAKeyProviderSingleton.getSingletonInstance();
    ecKeyProvider = new DefaultInMemoryECkeyProvider(ecParameterSpec);
  }

  /** {@inheritDoc} */
  @Override public KeyPair getSigningKeyPair(final @NonNull String keyType, final SignServiceContext context)
    throws KeyException {

    switch (keyType.toUpperCase()) {
    case "RSA":
      return rsaKeyProvider.getKeyPair();
    case "EC":
      return ecKeyProvider.getKeyPair();
    default:
      throw new KeyException("Unsupported key type");
    }

  }

  @Override public List<String> getSupportedKeyTypes() {
    return List.of("EC", "RSA");
  }
}
