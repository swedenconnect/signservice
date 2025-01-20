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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.Nonnull;
import se.swedenconnect.signservice.core.SignServiceHandler;

/**
 * A {@code BeanReferenceHandlerConfiguration} class is used when no actual handler configuration is made and instead an
 * already configured bean of the particular handler type is referenced using {@link #setBeanName(String)}. Of course
 * this can be performed using an sub-class of {@link AbstractHandlerFactory}, but the use of the
 * {@code BeanReferenceHandlerConfiguration} class has the advantage that is also checks that only {@code beanName} has
 * been assigned, and no sub-classing of {@link AbstractHandlerFactory} is needed.
 *
 * @param <T> the type of handlers being configured
 */
public class BeanReferenceHandlerConfiguration<T extends SignServiceHandler> extends AbstractHandlerConfiguration<T> {

  /** {@inheritDoc} */
  @Override
  public void init() throws Exception {
    if (this.getBeanName() == null) {
      throw new IllegalArgumentException("beanName must be set");
    }
    super.init();
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected String getDefaultFactoryClass() {
    return BeanReferenceHandlerFactory.class.getName();
  }

  /**
   * Only {@code beanName} may be assigned for custom handler configuration classes, so invoking this method will lead
   * to an {@link IllegalArgumentException} being thrown.
   */
  @Override
  public void setName(@Nonnull final String name) {
    if (name != null) {
      throw new IllegalArgumentException("name must not be assigned to custom config, only beanName is allowed");
    }
  }

  /**
   * Only {@code beanName} may be assigned for custom handler configuration classes, so invoking this method will lead
   * to an {@link IllegalArgumentException} being thrown.
   */
  @Override
  public void setDefaultConfig(@Nonnull final HandlerConfiguration<T> defaultConfig) {
    if (defaultConfig != null) {
      throw new IllegalArgumentException(
          "defaultConfig must not be assigned to custom config, only beanName is allowed");
    }
  }

  /**
   * Only {@code beanName} may be assigned for custom handler configuration classes, so invoking this method will lead
   * to an {@link IllegalArgumentException} being thrown.
   */
  @Override
  public void setDefaultConfigRef(@Nonnull final String defaultConfigRef) {
    if (defaultConfigRef != null) {
      throw new IllegalArgumentException(
          "defaultConfigRef must not be assigned to custom config, only beanName is allowed");
    }
  }

  /**
   * Will always return {@code false}.
   */
  @Override
  public boolean needsDefaultConfigResolving() {
    return false;
  }

  /**
   * The factory class used by the {@link BeanReferenceHandlerConfiguration} configuration class.
   */
  public static class BeanReferenceHandlerFactory<T extends SignServiceHandler> implements HandlerFactory<T> {

    /** The logger. */
    private static final Logger log = LoggerFactory.getLogger(BeanReferenceHandlerFactory.class);

    /**
     * Loads the externally configured bean.
     */
    @SuppressWarnings("unchecked")
    @Override
    public T create(@Nonnull final HandlerConfiguration<T> configuration, @Nonnull final BeanLoader beanLoader)
        throws IllegalArgumentException {
      if (configuration == null) {
        throw new IllegalArgumentException("Missing configuration");
      }
      if (configuration.getBeanName() == null) {
        throw new IllegalArgumentException("Missing bean-name property");
      }
      if (beanLoader == null) {
        throw new IllegalArgumentException(
            String.format("Can not load bean '{}' - No bean loader was supplied", configuration.getBeanName()));
      }
      log.debug("Factory {} supplied with configuration that contains bean-name '{}', loading bean ...",
          this.getClass().getSimpleName(), configuration.getBeanName());

      return (T) beanLoader.load(configuration.getBeanName(), Object.class);
    }

  }

}
