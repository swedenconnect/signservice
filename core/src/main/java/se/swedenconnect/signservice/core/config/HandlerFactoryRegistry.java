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

import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.annotation.Nonnull;

import se.swedenconnect.signservice.core.SignServiceHandler;

/**
 * The {@code HandlerFactoryRegistry} bean is a registry for {@link HandlerFactory} instances and may be used when
 * creating {@link SignServiceHandler} instances from {@link HandlerConfiguration} objects.
 */
public class HandlerFactoryRegistry {

  /** The registry of the factories created (or added). */
  private List<HandlerFactory<?>> registry = new ArrayList<>();

  /**
   * Based on a class name and a type, the method checks if this factory exists in the registry, and if not, attempts to
   * create it.
   * <p>
   * It is required that the factory class has a default (i.e., no-args) constructor.
   * </p>
   *
   * @param <T> the type of SignServiceHandler created by the factory
   * @param className the class name for the factory class
   * @param type the type of SignServiceHandler created by the factory
   * @return a HandlerFactory instance
   * @throws IllegalArgumentException if the HandlerFactory instance could not be created
   * @throws ClassCastException if the type does not match the factory
   */
  @Nonnull
  @SuppressWarnings("unchecked")
  public <T extends SignServiceHandler> HandlerFactory<T> getFactory(
      @Nonnull final String className, @Nonnull final Class<T> type)
      throws IllegalArgumentException, ClassCastException {

    HandlerFactory<?> factory = this.registry.stream()
        .filter(f -> f.getClass().getName().equals(className))
        .findFirst()
        .orElse(null);
    if (factory == null) {
      try {
        final Class<?> factoryClass = Class.forName(className);
        final Constructor<?> ctor = Arrays.stream(factoryClass.getDeclaredConstructors())
            .filter(c -> c.getParameterCount() == 0)
            .findFirst()
            .orElseThrow(
                () -> new IllegalArgumentException("No no-arg constructor visible for " + className));
        factory = (HandlerFactory<?>) ctor.newInstance();
        this.registry.add(factory);
      }
      catch (final ReflectiveOperationException e) {
        throw new IllegalArgumentException("Failed to create factory class - " + className, e);
      }
    }
    return (HandlerFactory<T>) factory;
  }

  /**
   * Adds a pre-created factory instance to the registry.
   *
   * @param factory the instance to add
   */
  public void addFactory(@Nonnull final HandlerFactory<?> factory) {
    this.registry.add(factory);
  }

}
