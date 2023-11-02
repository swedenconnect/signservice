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
package se.swedenconnect.signservice.config;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.core.SignServiceHandler;
import se.swedenconnect.signservice.core.config.BeanReferenceHandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * A base interface for handler configuration classes.
 * <p>
 * This interface is implemented by both configuration properties classes that are used for "default", or shared,
 * configuration and by configuration classes that are used to actually configure a handler instance (under engine
 * properties). A configuration properties class may contain several different possibilities to configure a handler
 * (i.e., different versions/variants of a particular handler). A configuration properties class used to configure a
 * handler may only contain one configuration, whereas a shared configuration object may contain several.
 * </p>
 *
 * @param <T> the type of handler being configured
 */
public interface HandlerConfigurationProperties<T extends SignServiceHandler> {

  /**
   * Gets the configuration that points to an already configured handler bean.
   *
   * @return a configuration that points to an already configured handler bean, or null if it is not assigned
   */
  @Nullable
  BeanReferenceHandlerConfiguration<T> getExternal();

  /**
   * Assigns the configuration that points to an already configured handler bean.
   *
   * @param external configuration that points to an already configured handler bean
   */
  void setExternal(@Nullable final BeanReferenceHandlerConfiguration<T> external);

  /**
   * An handler configuration properties class may have setters for several types of a particular types of a handler.
   * For a specific engine configuration only one may be assigned. This method returns the configuration that was set.
   *
   * @return the assigned configuration object
   * @throws IllegalArgumentException if more than one configuration type is supplied, or no configuration exists
   */
  @Nonnull
  HandlerConfiguration<T> getHandlerConfiguration() throws IllegalArgumentException;

  /**
   * Gets the handler configuration for the given name.
   *
   * @param name the name of the configuration
   * @return the handler configuration or null
   */
  @Nullable
  HandlerConfiguration<T> getHandlerConfiguration(@Nonnull final String name);

}
