/*
 * Copyright 2022-2025 Sweden Connect
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
package se.swedenconnect.signservice.core.config;

import jakarta.annotation.Nonnull;
import se.swedenconnect.security.credential.config.DefaultConfigurationResourceLoader;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;

/**
 * Singleton class holding a
 * {@link se.swedenconnect.security.credential.factory.PkiCredentialFactory PkiCredentialFactory}.
 *
 * @author Martin Lindström
 */
public class PkiCredentialFactorySingleton {

  /** The instance. */
  private static final PkiCredentialFactorySingleton INSTANCE = new PkiCredentialFactorySingleton();

  /** The credential factory. */
  private PkiCredentialFactory pkiCredentialFactory;

  /**
   * Gets the {@link PkiCredentialFactorySingleton} instance.
   *
   * @return the {@link PkiCredentialFactorySingleton} instance
   */
  @Nonnull
  public static PkiCredentialFactorySingleton getInstance() {
    return INSTANCE;
  }

  /**
   * Gets the {@link PkiCredentialFactory}.
   *
   * @return the {@link PkiCredentialFactory}
   */
  @Nonnull
  public synchronized PkiCredentialFactory getPkiCredentialFactory() {
    if (this.pkiCredentialFactory == null) {
      this.pkiCredentialFactory = this.createDefaultPkiCredentialFactory();
    }
    return this.pkiCredentialFactory;
  }

  /**
   * Assigns the credential factory to use as a singleton.
   *
   * @param pkiCredentialFactory credential factory
   */
  public synchronized void setPkiCredentialFactory(@Nonnull final PkiCredentialFactory pkiCredentialFactory) {
    if (pkiCredentialFactory == null) {
      throw new IllegalArgumentException("PkiCredentialFactory cannot be null");
    }
    this.pkiCredentialFactory = pkiCredentialFactory;
  }

  /**
   * Creates a default {@link PkiCredentialFactory} (with no possibilities to handle credential bundles).
   *
   * @return a {@link PkiCredentialFactory}
   */
  @Nonnull
  private PkiCredentialFactory createDefaultPkiCredentialFactory() {
    return new PkiCredentialFactory(null, new DefaultConfigurationResourceLoader(), true);
  }

  // Hidden constructor
  private PkiCredentialFactorySingleton() {
  }

}
