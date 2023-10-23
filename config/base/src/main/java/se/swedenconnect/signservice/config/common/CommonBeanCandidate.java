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
package se.swedenconnect.signservice.config.common;

import jakarta.annotation.Nonnull;
import jakarta.annotation.PostConstruct;

/**
 * An interface that is implemented by subclasses of configuration classes that may be instantiated as "common beans",
 * see {@link CommonBeansConfigurationProperties}.
 */
public interface CommonBeanCandidate {

  /**
   * The bean name that should be assigned.
   *
   * @return the bean name
   */
  @Nonnull
  String getBeanName();

  /**
   * The bean name that should be assigned.
   *
   * @param beanName the bean name
   */
  void setBeanName(@Nonnull final String beanName);

  /**
   * Method that is invoked by the framework after all settings have been assigned. The implementation checks that all
   * necessary settings are assigned.
   *
   * @throws IllegalArgumentException for configuration errors
   */
  @PostConstruct
  void afterPropertiesSet() throws IllegalArgumentException;

}
