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
package se.swedenconnect.signservice.config;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.application.SignServiceEngineManager;
import se.swedenconnect.signservice.core.config.BeanLoader;

/**
 * The {@code SignServiceFactory} is responsible of setting up the required instances (beans) needed for a SignService
 * application.
 */
public interface SignServiceFactory {

  /**
   * Creates a {@link SignServiceEngineManager} based on the supplied configuration.
   *
   * @param configuration the SignService configuration
   * @param beanLoader the bean loader. If not supplied and the configuration contains bean references the method will
   *          fail
   * @param beanRegistrator a bean registration callback (optional)
   * @return a SignServiceEngineManager instance
   * @throws Exception if the configuration is incorrect and a SignServiceEngineManager can not be created
   */
  @Nonnull
  SignServiceEngineManager createSignServiceEngineManager(
      @Nonnull final SignServiceConfigurationProperties configuration,
      @Nullable final BeanLoader beanLoader,
      @Nullable final BeanRegistrator beanRegistrator) throws Exception;

}
