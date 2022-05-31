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

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.certificate.base.keyprovider.KeyProvider;
import se.swedenconnect.signservice.certificate.base.keyprovider.SignServiceSigningKeyProvider;
import se.swedenconnect.signservice.session.SignServiceContext;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.security.KeyException;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

/**
 * Implementation of a default key provider.
 */
public class DefaultSignServiceSigningKeyProvider implements SignServiceSigningKeyProvider {

  private final KeyProvider rsaKeyProvider;
  private final KeyProvider ecKeyProvider;

  /**
   * Constructor for a default sign service key provider using the following preset parameters:
   *
   * <ul>
   * <li>RSA key length 3072 bits</li>
   * <li>RSA pre-produced key stack size = 100 keys</li>
   * <li>EC curve NIST P-256</li>
   * </ul>
   */
  public DefaultSignServiceSigningKeyProvider() {
    StackedRSAKeyProviderSingleton.setInstance(new DefaultStackedInMemoryRSAKeyProvider(3072, 100));
    this.rsaKeyProvider = StackedRSAKeyProviderSingleton.getSingletonInstance();
    this.ecKeyProvider = new DefaultInMemoryECkeyProvider(new ECGenParameterSpec("P-256"));
  }

  /**
   * Constructor for default key provider.
   *
   * @param rsaKeyLen key size of the generated RSA keys
   * @param rsaStackSize number of pre-produced RSA keys kept in the key generator
   * @param ecParameterSpec the EC curve to use for generating EC keys
   */
  public DefaultSignServiceSigningKeyProvider(final int rsaKeyLen, final int rsaStackSize,
      @Nonnull final ECGenParameterSpec ecParameterSpec) {
    StackedRSAKeyProviderSingleton.setInstance(new DefaultStackedInMemoryRSAKeyProvider(rsaKeyLen, rsaStackSize));
    this.rsaKeyProvider = StackedRSAKeyProviderSingleton.getSingletonInstance();
    this.ecKeyProvider = new DefaultInMemoryECkeyProvider(ecParameterSpec);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public PkiCredential getSigningKeyPair(@Nonnull final String keyType) throws KeyException {
    return this.getSigningKeyPair(keyType, null);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public PkiCredential getSigningKeyPair(@Nonnull final String keyType, @Nullable final SignServiceContext context)
      throws KeyException {

    switch (keyType.toUpperCase()) {
    case "RSA":
      return this.rsaKeyProvider.getKeyPair();
    case "EC":
      return this.ecKeyProvider.getKeyPair();
    default:
      throw new KeyException("Unsupported key type");
    }

  }

  /** {@inheritDoc} '*/
  @Override
  @Nonnull
  public List<String> getSupportedKeyTypes() {
    return List.of("EC", "RSA");
  }
}
