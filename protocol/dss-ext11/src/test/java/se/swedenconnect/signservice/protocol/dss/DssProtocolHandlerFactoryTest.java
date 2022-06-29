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
package se.swedenconnect.signservice.protocol.dss;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.core.config.AbstractHandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;
import se.swedenconnect.signservice.protocol.ProtocolHandler;

/**
 * Test cases for DssProtocolHandlerFactory.
 */
public class DssProtocolHandlerFactoryTest {

  @Test
  public void testCreate() {
    final DssProtocolHandlerFactory factory = new DssProtocolHandlerFactory();
    final DssProtocolHandlerConfiguration conf = new DssProtocolHandlerConfiguration();
    final ProtocolHandler handler = factory.create(conf);
    Assertions.assertTrue(DssProtocolHandler.class.isInstance(handler));
  }

  @Test
  public void testCreateNoConf() {
    final DssProtocolHandlerFactory factory = new DssProtocolHandlerFactory();
    final ProtocolHandler handler = factory.create(null);
    Assertions.assertTrue(DssProtocolHandler.class.isInstance(handler));
  }

  @Test
  public void testCreateBadConf() {
    final DssProtocolHandlerFactory factory = new DssProtocolHandlerFactory();
    final HandlerConfiguration<ProtocolHandler> conf = new AbstractHandlerConfiguration<ProtocolHandler>() {

      @Override
      protected String getDefaultFactoryClass() {
        return DssProtocolHandlerFactory.class.getName();
      }
    };
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      factory.create(conf);
    });

  }

}
