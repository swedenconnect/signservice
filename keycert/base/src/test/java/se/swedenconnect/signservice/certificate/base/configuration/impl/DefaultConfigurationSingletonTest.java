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

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import se.swedenconnect.signservice.certificate.base.configuration.DefaultConfiguration;
import se.swedenconnect.signservice.certificate.base.configuration.DefaultParameter;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Default configuration singleton test
 */
@Slf4j
class DefaultConfigurationSingletonTest {

  @Test
  void getSingletonInstance() {
    log.info("Default singleton configuration test");
    DefaultConfiguration defaultConfiguration = DefaultConfigurationSingleton.getSingletonInstance();
    defaultConfiguration.put(DefaultParameter.certificateProfile.getParameterName(), "profile1");

    // Get the singleton instance
    DefaultConfiguration defaultConfiguration2 = DefaultConfigurationSingleton.getSingletonInstance();

    // Check that the new instance has the data of the first instance
    assertEquals("profile1", defaultConfiguration2.get(DefaultParameter.certificateProfile.getParameterName(), null, String.class));

    // Set a new empty instance
    DefaultConfigurationSingleton.setInstance(new KeyAndCertModuleDefaultConfiguration());
    DefaultConfiguration newDefaultConfig = DefaultConfigurationSingleton.getSingletonInstance();

    // Check that the new empty instance holds no data
    assertNull(newDefaultConfig.get(DefaultParameter.certificateProfile.getParameterName(), null, String.class));

  }
}