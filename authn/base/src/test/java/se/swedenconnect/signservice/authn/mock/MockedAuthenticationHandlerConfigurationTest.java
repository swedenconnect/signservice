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

/**
 * Test cases for MockedAuthenticationHandlerConfiguration.
 */
public class MockedAuthenticationHandlerConfigurationTest {

  @Test
  public void testActiveDefault() {
    final MockedAuthenticationHandlerConfiguration conf = new MockedAuthenticationHandlerConfiguration();
    Assertions.assertFalse(conf.isActive());
  }

  @Test
  public void testSetActive() {
    final MockedAuthenticationHandlerConfiguration conf = new MockedAuthenticationHandlerConfiguration();
    conf.setActive(true);
    Assertions.assertTrue(conf.isActive());
  }

  @Test
  public void testFactoryClass() {
    final MockedAuthenticationHandlerConfiguration conf = new MockedAuthenticationHandlerConfiguration();
    Assertions.assertEquals(MockedAuthenticationHandlerFactory.class.getName(), conf.getFactoryClass());
  }

}
