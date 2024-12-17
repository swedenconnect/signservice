/*
 * Copyright 2022-2024 Sweden Connect
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

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

import jakarta.annotation.Nonnull;
import jakarta.annotation.PostConstruct;

/**
 * Generic validation configuration settings.
 */
public class ValidationConfiguration {

  /** The default allowed clock skew is 30 seconds. */
  public static final Duration DEFAULT_ALLOWED_CLOCK_SKEW = Duration.ofSeconds(30);

  /** The default setting for the maximum age of a message is 3 minutes. */
  public static final Duration DEFAULT_MAX_MESSAGE_AGE = Duration.ofMinutes(3);

  /** The clock skew that we accept during checks of time stamps. */
  private Duration allowedClockSkew;

  /**
   * The maximum amount of time that has passed since a message we are receiving was sent. This is based on the
   * message's "created-at" property (or similar).
   */
  private Duration maxMessageAge;

  /**
   * The clock skew that we accept during checks of time stamps.
   *
   * @return the allowed clock skew
   */
  @Nonnull
  public Duration getAllowedClockSkew() {
    return Optional.ofNullable(this.allowedClockSkew).orElseGet(() -> DEFAULT_ALLOWED_CLOCK_SKEW);
  }

  /**
   * The clock skew that we accept during checks of time stamps.
   *
   * @param allowedClockSkew the allowed clock skew
   */
  public void setAllowedClockSkew(@Nonnull final Duration allowedClockSkew) {
    if (this.allowedClockSkew != null) {
      throw new IllegalArgumentException("allowedClockSkew has already been assigned");
    }
    this.allowedClockSkew = Objects.requireNonNull(allowedClockSkew, "allowedClockSkew must not be null");
  }

  /**
   * The maximum amount of time that has passed since a message we are receiving was sent. This is based on the
   * message's "created-at" property (or similar).
   *
   * @return the maximum message age
   */
  @Nonnull
  public Duration getMaxMessageAge() {
    return Optional.ofNullable(this.maxMessageAge).orElseGet(() -> DEFAULT_MAX_MESSAGE_AGE);
  }

  /**
   * The maximum amount of time that has passed since a message we are receiving was sent. This is based on the
   * message's "created-at" property (or similar).
   *
   * @param maxMessageAge the maximum message age
   */
  public void setMaxMessageAge(@Nonnull final Duration maxMessageAge) {
    if (this.maxMessageAge != null) {
      throw new IllegalArgumentException("maxMessageAge has already been assigned");
    }
    this.maxMessageAge = Objects.requireNonNull(maxMessageAge, "maxMessageAge must not be null");
  }

  /**
   * Initializes the {@code ValidationConfigurationSingleton} so that the configuration is accesible
   * using from {@link AbstractHandlerFactory}.
   */
  @PostConstruct
  public void init() {
    ValidationConfigurationSingleton.initializeSingleton(this);
  }

}
