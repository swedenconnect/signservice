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
package se.swedenconnect.signservice.authn.mock;

import jakarta.annotation.Nonnull;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.core.config.AbstractHandlerConfiguration;

/**
 * Configuration class for creating {@link MockedAuthenticationHandler} instances.
 */
public class MockedAuthenticationHandlerConfiguration extends AbstractHandlerConfiguration<AuthenticationHandler> {

  /**
   * Whether the mock handler is active.
   */
  private Boolean active;

  /**
   * Tells whether the mock handler is active, i.e., whether the configuration should create a
   * {@link MockedAuthenticationHandler} instance.
   *
   * @return whether the mock handler is active
   */
  public boolean isActive() {
    return this.active != null ? this.active : false;
  }

  /**
   * Assigns whether the mock handler is active, i.e., whether the configuration should create a
   * {@link MockedAuthenticationHandler} instance.
   *
   * @param active whether the mock handler is active
   */
  public void setActive(final boolean active) {
    this.active = active;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected String getDefaultFactoryClass() {
    return MockedAuthenticationHandlerFactory.class.getName();
  }

}
