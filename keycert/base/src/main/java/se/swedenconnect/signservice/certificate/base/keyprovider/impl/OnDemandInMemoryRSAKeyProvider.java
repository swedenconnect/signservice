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

import java.security.KeyException;

import javax.annotation.Nonnull;

import se.swedenconnect.security.credential.PkiCredential;

/**
 * RSA key provider generating RSA keys on demand. This differs from the stacked RSA key
 * provider that pre-generates RSA keys in a background thread to optimize the time
 * it takes to obtain a key.
 */
public class OnDemandInMemoryRSAKeyProvider extends AbstractRSAKeyProvider {

  /**
   * Constructor for the on-demand RSA key provider.
   *
   * @param keySize key size for generated RSA keys
   */
  public OnDemandInMemoryRSAKeyProvider(final int keySize) {
    super(keySize);
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public PkiCredential getKeyPair() throws KeyException {
    return this.generateKeyPair();
  }

}
