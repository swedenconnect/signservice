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
package se.swedenconnect.signservice.authn.mock;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.core.config.AbstractHandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Test cases for MockedAuthenticationHandlerFactory.
 */
public class MockedAuthenticationHandlerFactoryTest {

  @Test
  public void testCreate() {
    final MockedAuthenticationHandlerFactory factory = new MockedAuthenticationHandlerFactory();
    final MockedAuthenticationHandlerConfiguration conf = new MockedAuthenticationHandlerConfiguration();
    conf.setName("Mocked");
    conf.setActive(true);

    final AuthenticationHandler handler = factory.create(conf);
    Assertions.assertTrue(MockedAuthenticationHandler.class.isInstance(handler));
    Assertions.assertEquals("Mocked", handler.getName());
  }

  @Test
  public void testCreateNullConf() {
    final MockedAuthenticationHandlerFactory factory = new MockedAuthenticationHandlerFactory();

    final AuthenticationHandler handler = factory.create(null);
    Assertions.assertTrue(MockedAuthenticationHandler.class.isInstance(handler));
    Assertions.assertEquals(MockedAuthenticationHandler.class.getSimpleName(), handler.getName());
  }

  @Test
  public void testNotActive() {
    final MockedAuthenticationHandlerFactory factory = new MockedAuthenticationHandlerFactory();
    final MockedAuthenticationHandlerConfiguration conf = new MockedAuthenticationHandlerConfiguration();
    conf.setActive(false);

    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      factory.create(conf);
    });
  }

  @Test
  public void testBadConf() {
    final MockedAuthenticationHandlerFactory factory = new MockedAuthenticationHandlerFactory();
    final HandlerConfiguration<AuthenticationHandler> conf = new AbstractHandlerConfiguration<AuthenticationHandler>() {

      @Override
      protected String getDefaultFactoryClass() {
        return MockedAuthenticationHandlerFactory.class.getName();
      }
    };
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      factory.create(conf);
    });
  }

  @Test
  public void testHandlerType() {
    final MockedAuthenticationHandlerFactory2 factory = new MockedAuthenticationHandlerFactory2();
    Assertions.assertEquals(AuthenticationHandler.class, factory.handler());
  }

  private static class MockedAuthenticationHandlerFactory2 extends MockedAuthenticationHandlerFactory {

    public Class<AuthenticationHandler> handler() {
      return this.getHandlerType();
    }

  }

}
