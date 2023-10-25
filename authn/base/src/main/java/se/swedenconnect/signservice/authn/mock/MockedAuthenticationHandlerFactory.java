/*
 * Copyright 2022-2023 Sweden Connect
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
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.core.config.AbstractHandlerFactory;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Factory for creating {@link MockedAuthenticationHandler} instances.
 */
public class MockedAuthenticationHandlerFactory extends AbstractHandlerFactory<AuthenticationHandler> {

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected AuthenticationHandler createHandler(
      @Nullable final HandlerConfiguration<AuthenticationHandler> configuration, @Nullable final BeanLoader beanLoader)
      throws IllegalArgumentException {

    final MockedAuthenticationHandler handler = new MockedAuthenticationHandler();
    if (configuration != null) {
      if (!MockedAuthenticationHandlerConfiguration.class.isInstance(configuration)) {
        throw new IllegalArgumentException(
            "Unsupported authentication handler configuration class: " + configuration.getClass().getName());
      }
      if (!((MockedAuthenticationHandlerConfiguration) configuration).isActive()) {
        throw new IllegalArgumentException(
            String.format("%s is not active - illegal call", this.getClass().getSimpleName()));
      }
      handler.setName(configuration.getName());
    }
    return handler;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected Class<AuthenticationHandler> getHandlerType() {
    return AuthenticationHandler.class;
  }

}
