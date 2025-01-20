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

import java.util.Objects;
import java.util.Optional;

import jakarta.annotation.Nonnull;

/**
 * A singleton that enables any handler factory implementation to access the {@link ValidationConfiguration} using the
 * {@code getValidationConfig()} method of the {@link AbstractHandlerFactory} class.
 * <p>
 * Note that this class is package private to prevent it from being used directly in handler implementations, thus
 * making the dependent on a particular way of configuration (which we don't want).
 * </p>
 */
class ValidationConfigurationSingleton {

  /** The validation configuration. */
  private ValidationConfiguration validationConfiguration;

  /** The singleton. */
  private static final ValidationConfigurationSingleton instance = new ValidationConfigurationSingleton();

  /**
   * Gets the validation configuration.
   *
   * @return a ValidationConfiguration object
   */
  @Nonnull
  public static ValidationConfiguration getConfig() {
    return Optional.ofNullable(instance.validationConfiguration)
        .orElseGet(() -> new ValidationConfiguration());
  }

  /**
   * Initializes the singleton with the configured {@link ValidationConfiguration} object.
   *
   * @param validationConfiguration the validation configuration
   */
  public static void initializeSingleton(@Nonnull final ValidationConfiguration validationConfiguration) {
    if (instance.validationConfiguration == null) {
      instance.validationConfiguration =
          Objects.requireNonNull(validationConfiguration, "validationConfiguration must not be null");
    }
  }

  // Hidden constructor
  private ValidationConfigurationSingleton() {
  }

}
