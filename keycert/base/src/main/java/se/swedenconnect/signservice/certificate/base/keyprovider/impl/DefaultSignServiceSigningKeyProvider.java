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
import java.util.List;

/**
 * Implementation of a default key provider.
 */
public class DefaultSignServiceSigningKeyProvider implements SignServiceSigningKeyProvider {

  private final KeyProvider rsaKeyProvider;
  private final KeyProvider ecKeyProvider;

  /**
   * Constructor for the default sign service key provider
   * @param rsaKeyProvider key provider for generating RSA keys
   * @param ecKeyProvider key provider for generating EC keys
   */
  public DefaultSignServiceSigningKeyProvider(
    KeyProvider rsaKeyProvider, KeyProvider ecKeyProvider) {
    this.rsaKeyProvider = rsaKeyProvider;
    this.ecKeyProvider = ecKeyProvider;
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
