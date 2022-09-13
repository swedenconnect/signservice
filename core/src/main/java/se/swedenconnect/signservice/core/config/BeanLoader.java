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

/**
 * A bean loader interface accepts a bean name and returns a handler instance.
 */
@FunctionalInterface
public interface BeanLoader {

  /**
   * Loads a bean having the given bean name.
   *
   * @param <T> the type of the bean
   * @param beanName the bean name
   * @param type the type of the bean
   * @return the loaded bean
   */
  <T> T load(@Nonnull final String beanName, @Nonnull final Class<T> type);

}
