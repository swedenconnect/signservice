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

import java.util.function.Function;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.annotation.PostConstruct;
import se.swedenconnect.signservice.core.SignServiceHandler;

/**
 * Base interface for the configuration of a handler. Implementing classes are expected to supply setters and getters
 * for all properties that should be config-data for that specific type of configuration class.
 * <p>
 * The general idea is that a particular handler should always be "stand-alone", i.e., it should possible to create a
 * handler by manually assigning all of its required configuration data without the use of a
 * {@code HandlerConfiguration} data object. The {@code HandlerConfiguration} is intended to be used when SignService
 * handlers are configured, and created in an application from properties, or YML-files, for example using Spring Boot
 * or Quarkus.
 * </p>
 * <p>
 * Each class implementing the {@code HandlerConfiguration} must tell which {@link HandlerFactory} class that
 * understands its settings and can be used to create a handler based on the configuration. See {@link #getFactoryClass()}.
 * </p>
 * <p>
 * Note: An implementing class must not assign a default value for any property. Non-assigned properties must always
 * return {@code null}. Assignment of default values should be done in the corresponding factory class.
 * </p>
 *
 * @param <T> the type of handler the configuration is for
 */
public interface HandlerConfiguration<T extends SignServiceHandler> {

  /**
   * Gets the class name of the factory class that should be used to create handlers based on this configuration.
   * <p>
   * Normally, this should be hardwired into a specific configuration implementation, but for the sake of maximum
   * configurability, it is also possible to override the default using {@link #setFactoryClass(String)}.
   * </p>
   *
   * @return the class name for the factory
   */
  @Nonnull
  String getFactoryClass();

  /**
   * Sets the factory class name of the factory that should be used to create handler instances based on this
   * configuration. The handler class referenced must have a default (i.e., no-arg) constructor.
   * <p>
   * A class implementing {@link HandlerConfiguration} should always supply a default class name for the factory that
   * should be used, so this method is only to be used in the cases where the default should be overridden.
   * </p>
   *
   * @param factoryClass the factory class name
   */
  void setFactoryClass(@Nonnull final String factoryClass);

  /**
   * Assigns the name that the handler should be given.
   *
   * @param name the handler name
   */
  void setName(@Nonnull final String name);

  /**
   * Gets the configured handler name.
   *
   * @return the handler name, or null if none has been assigned
   */
  @Nullable
  String getName();

  /**
   * In many cases, handlers of the same type share many configuration settings. Therefore, a default configuration may
   * be assigned to the configuration object. Any settings applied directly to the configuration object always overrides
   * the setting from the supplied default configuration.
   *
   * @param defaultConfig a default configuration object
   */
  void setDefaultConfig(@Nonnull final HandlerConfiguration<T> defaultConfig);

  /**
   * Gets the assigned default configuration. After a merge this method will return {@code null}. See
   * {@link #setDefaultConfig(HandlerConfiguration)} for details.
   *
   * @return the assigned default configuration or null if none has been assigned
   */
  @Nullable
  HandlerConfiguration<T> getDefaultConfig();

  /**
   * When configuration objects are created using Spring Boot's {@code ConfigurationProperties} paradigm, or perhaps
   * according another framework's way of handling configuration objects from properties files, we may not be able to
   * assign a created {@link HandlerConfiguration} object. Instead, the property file, that is the base for how the
   * configuration objects are created, can contain the {@code defaultConfigRef} property that points at a named
   * reference of a default configuration (that has been created earlier in the process).
   * <p>
   * The use of configuration references requires that the reference is resolved before it is used. See
   * {@link #resolveDefaultConfigRef(Function)}.
   * </p>
   *
   * @param defaultConfigRef the name of the default configuration reference
   */
  void setDefaultConfigRef(@Nonnull final String defaultConfigRef);

  /**
   * Gets the default configuration reference (if assigned). See {@link #setDefaultConfig(HandlerConfiguration)}.
   *
   * @return the default configuration reference or null
   */
  @Nullable
  String getDefaultConfigRef();

  /**
   * Predicate that tells whether the configuration object needs to be "resolved" before it can be used. If
   * {@link #setDefaultConfigRef(String)} has been invoked during the creation of the object the method will return
   * {@code true} and the {@link #resolveDefaultConfigRef(Function)} should be invoked before the class instance is put
   * into service.
   *
   * @return true if {@link #resolveDefaultConfigRef(Function)} needs to be called and false otherwise
   */
  boolean needsDefaultConfigResolving();

  /**
   * If a default configuration reference has been assigned ({@link #needsDefaultConfigResolving()} returns
   * {@code true}) the reference needs to be resolved into a {@link HandlerConfiguration} object, and this object needs
   * to be merged with our configuration instance. This is typically done after the framework that loads the
   * configuration properties has completed its work in instantiating configuration objects.
   *
   * @param resolver the resolver that knows how to locate a configuration object based on a supplied reference.
   * @throws NullPointerException if the resolver returns null
   * @throws IllegalArgumentException if resolver finds a default config object, but the merge operation fails
   */
  void resolveDefaultConfigRef(@Nonnull final Function<String, HandlerConfiguration<T>> resolver)
      throws NullPointerException, IllegalArgumentException;

  /**
   * A {@code beanName} of a handler bean may be assigned the configuration object. This effectively cancels the
   * configuration, and the factory will not create a new handler object, instead it will just load the bean using the
   * supplied {@code beanName}.
   * <p>
   * Note that it is an error to assign any other configuration data if the {@code beanName} is assigned.
   * </p>
   *
   * @param beanName the bean name
   */
  void setBeanName(@Nonnull final String beanName);

  /**
   * Gets the {@code beanName} property. See {@link #setBeanName(String)} for the purpose of assigning a bean name to a
   * configuration object.
   *
   * @return the bean name to use, or null if no pre-created bean should be used
   */
  @Nullable
  String getBeanName();

  /**
   * Should be invoked after all properties have been assigned to ensure that the setup of the instance has been
   * performed correctly. Note also means that resolving of default configuration should have been done before
   * invocation of this method. Therefore, the {@code init} method is invoked "manually" and not be the bean framework
   * (by using for example {@link PostConstruct}).
   *
   * @throws Exception for initialization errors
   */
  void init() throws Exception;

}
