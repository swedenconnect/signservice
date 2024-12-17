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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.core.SignServiceHandler;

/**
 * A handler factory is used to create instances of {@link SignServiceHandler} based on a supplied
 * {@link HandlerConfiguration}.
 *
 * @param <T> the type of handlers being created
 */
public interface HandlerFactory<T extends SignServiceHandler> {

  /**
   * Creates a handler instance based on the supplied configuration. The {@code beanLoader} must be supplied if the
   * configuration contains a {@code beanName} reference (see {@link HandlerConfiguration#getBeanName()}).
   *
   * @param configuration the configuration. May be null if the factory can create a handler instance without any
   *          configuration
   * @param beanLoader the bean loader
   * @return a handler instance
   * @throws IllegalArgumentException if the supplied configuration is not correct
   */
  @Nonnull
  T create(@Nullable final HandlerConfiguration<T> configuration, @Nullable final BeanLoader beanLoader)
      throws IllegalArgumentException;

  /**
   * Creates a handler instance based on the supplied configuration.
   * <p>
   * If the configuration object contains a {@code beanName} reference this method will fail since no bean loader is
   * supplied.
   * </p>
   *
   * @param configuration the configuration. May be null if the factory can create a handler instance without any
   *          configuration
   * @return a handler instance
   * @throws IllegalArgumentException if the supplied configuration is not correct
   */
  @Nonnull
  default T create(@Nullable final HandlerConfiguration<T> configuration) throws IllegalArgumentException {
    return this.create(configuration, null);
  }

}
