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
package se.swedenconnect.signservice.core.config;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.signservice.core.SignServiceHandler;

/**
 * Abstract base implementation of the {@link HandlerFactory} interface.
 *
 * @param <T> the type of handler being created
 */
public abstract class AbstractHandlerFactory<T extends SignServiceHandler> implements HandlerFactory<T> {

  /** The logger. */
  private static final Logger log = LoggerFactory.getLogger(AbstractHandlerFactory.class);

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public final T create(@Nullable final HandlerConfiguration<T> configuration, @Nullable final BeanLoader beanLoader)
      throws IllegalArgumentException {
    if (configuration != null) {
      if (configuration.getBeanName() != null) {
        if (beanLoader == null) {
          throw new IllegalArgumentException(
              String.format("Can not load bean '{}' - No bean loader was supplied", configuration.getBeanName()));
        }
        log.debug("Factory {} supplied with configuration that contains bean-name '{}', loading bean ...",
            this.getClass().getSimpleName(), configuration.getBeanName());

        return beanLoader.load(configuration.getBeanName(), this.getHandlerType());
      }
      if (configuration.needsDefaultConfigResolving()) {
        final String msg = "Configuration contains an unresolved default configuration reference";
        log.error("{}", msg);
        throw new IllegalArgumentException(msg);
      }
    }
    return this.createHandler(configuration, beanLoader);
  }

  /**
   * Creates a handler instance based on the supplied configuration. The method is invoked from
   * {@link #create(HandlerConfiguration)} that already has taken care of bean loading (if necessary) and checking the
   * any references have been resolved. The {@code beanLoader} is supplied anyway since the implementation may need to
   * load any other bean references.
   *
   * @param configuration the configuration. May be null if the factory can create a handler instance without any
   *          configuration
   * @param beanLoader the bean loader (may be null)
   * @return a handler instance
   * @throws IllegalArgumentException if the supplied configuration is not correct
   */
  @Nonnull
  protected abstract T createHandler(
      @Nullable final HandlerConfiguration<T> configuration, @Nullable final BeanLoader beanLoader)
      throws IllegalArgumentException;

  /**
   * Gets the handler type.
   *
   * @return the handler type
   */
  protected abstract Class<T> getHandlerType();

  /**
   * Gets the application wide {@link ValidationConfiguration} object.
   *
   * @return the ValidationConfiguration
   */
  @Nonnull
  protected ValidationConfiguration getValidationConfig() {
    return ValidationConfigurationSingleton.getConfig();
  }

}
