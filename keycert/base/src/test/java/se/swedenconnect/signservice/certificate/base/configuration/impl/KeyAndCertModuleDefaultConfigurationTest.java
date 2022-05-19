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

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for Configuration class
 */
@Slf4j
class KeyAndCertModuleDefaultConfigurationTest {

  @Test
  void getSingletonInstance() {
    DefaultConfiguration singletonInstance = DefaultConfigurationSingleton.getSingletonInstance();
    assertTrue(DefaultConfiguration.class.isAssignableFrom(singletonInstance.getClass()));
    log.info("Singleton instance is created as subclass of DefaultConfiguration");
  }

  @Test
  void put() {
    String param1Name = "param1";
    String param2Name = "param2";
    String param3Name = "param3";
    String param1Val = "param1Val";
    int param2Val = 12345;
    BigInteger param3Val = BigInteger.TEN;
    String client1Id = "client1";
    String client2Id = "client2";

    DefaultConfigurationSingleton.setInstance(new KeyAndCertModuleDefaultConfiguration());
    DefaultConfiguration config = DefaultConfigurationSingleton.getSingletonInstance();
    config.put(param1Name, param1Val);
    config.put(param2Name, param2Val);
    config.put(param3Name, param3Val, client1Id);

    assertEquals(param1Val, config.get(param1Name, null));
    log.info("Successfully getting default generic String parameter");
    assertEquals(param1Val, config.get(param1Name, client1Id));
    log.info("Successfully getting default generic String parameter for specific client ID");
    assertEquals(param2Val, config.get(param2Name, null));
    log.info("Successfully getting default generic int parameter");
    assertEquals(param2Val, config.get(param2Name, client1Id));
    log.info("Successfully getting default generic int parameter for specific client ID");
    assertEquals(null, config.get(param3Name, null));
    log.info("Getting null parameter value for parameter set only for specific client ID when doing a generic request");
    assertEquals(param3Val, config.get(param3Name, client1Id));
    log.info("Successfully getting client specific generic BigInteger parameter for specific client ID");
    assertEquals(null, config.get(param3Name, client2Id));
    log.info(
      "Getting null parameter value for parameter set only for specific client ID when doing a request for another client ID");

    assertThrows(ClassCastException.class, () -> config.get(param3Name, client1Id, String.class));
    log.info("Asking for parameter with wrong class cause ClassCastException");
    assertThrows(NullPointerException.class, () -> config.get(null, client1Id));
    log.info("Request for value with null parameter name cause NullPointerException");
  }

}