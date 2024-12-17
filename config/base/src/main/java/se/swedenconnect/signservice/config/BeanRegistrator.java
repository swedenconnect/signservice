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
package se.swedenconnect.signservice.config;

import jakarta.annotation.Nonnull;

/**
 * An interface describing a callback that is used by
 * {@link SignServiceFactory#createSignServiceEngineManager(SignServiceConfigurationProperties, se.swedenconnect.signservice.core.config.BeanLoader, BeanRegistrator)}
 * to register beans.
 */
public interface BeanRegistrator {

  /**
   * Registers a bean with the given name.
   *
   * @param <T> the type of the bean
   * @param beanName the bean name
   * @param type the type of the bean
   * @param bean the bean
   * @throws Exception for bean registration errors
   */
  <T> void registerBean(@Nonnull final String beanName, @Nonnull final Class<T> type, @Nonnull final T bean)
      throws Exception;

}
