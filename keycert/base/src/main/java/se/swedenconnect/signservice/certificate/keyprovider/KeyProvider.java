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

import javax.annotation.Nonnull;

import se.swedenconnect.security.credential.PkiCredential;

/**
 * Interface for a key provider.
 *
 * The key pair is returned as a {@link PkiCredential} to accommodate for the situation where the key may be provided as
 * a key from an HSM where the access to the key need special support in order to assure that the key is still available
 * etc.
 */
public interface KeyProvider {

  /**
   * Get a new key pair.
   *
   * @return a key pair delivered as {@link PkiCredential}
   * @throws KeyException on error obtaining a key pair
   */
  @Nonnull
  PkiCredential getKeyPair() throws KeyException;

  /**
   * Predicate that tells whether the supplied key type is supported by the provider.
   *
   * @param keyType the key type to test
   * @return true if the key type is supported and false otherwise
   */
  boolean supports(@Nonnull final String keyType);

}
