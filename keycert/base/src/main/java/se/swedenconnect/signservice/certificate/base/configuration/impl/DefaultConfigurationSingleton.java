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
package se.swedenconnect.signservice.certificate.base.configuration.impl;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.signservice.certificate.base.configuration.DefaultConfiguration;

/**
 * Class providing a singleton instance of default configuration parameters.
 */
@Slf4j
public class DefaultConfigurationSingleton {

  /** Prevent instantiation. */
  private DefaultConfigurationSingleton() {
  }

  /**
   * Default configuration class singleton instance.
   *
   * @param instance the instance of default configuration data to use as singleton
   */
  @Setter
  private static volatile DefaultConfiguration instance;

  /**
   * Get a singleton instance of the default configuration.
   *
   * @return default configuration
   */
  public static DefaultConfiguration getSingletonInstance() {
    if (instance == null) {
      log.info("No singleton instance is set");
      synchronized (DefaultConfigurationSingleton.class) {
        if (instance == null) {
          instance = new KeyAndCertModuleDefaultConfiguration();
          log.info("Setting new default configuration data instance of class {}", instance.getClass().getName());
        }
      }
    }
    return instance;
  }

}
