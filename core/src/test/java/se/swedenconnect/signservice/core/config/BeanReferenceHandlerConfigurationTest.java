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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.core.AbstractSignServiceHandler;

/**
 * Test cases for BeanReferenceHandlerConfiguration.
 */
public class BeanReferenceHandlerConfigurationTest {

  @Test
  public void testUsage() {
    final BeanReferenceHandlerConfiguration<DummyHandler> conf = new BeanReferenceHandlerConfiguration<>();
    conf.setBeanName("the.bean");
    Assertions.assertDoesNotThrow(() -> {
      conf.init();
    });
    Assertions.assertEquals(BeanReferenceHandlerConfiguration.BeanReferenceHandlerFactory.class.getName(),
        conf.getFactoryClass());
    Assertions.assertFalse(conf.needsDefaultConfigResolving());
  }

  @Test
  public void testMissingBeanName() {
    final BeanReferenceHandlerConfiguration<DummyHandler> conf = new BeanReferenceHandlerConfiguration<>();
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      conf.init();
    });
  }

  @Test
  public void illegalAssignments() {
    final BeanReferenceHandlerConfiguration<DummyHandler> conf = new BeanReferenceHandlerConfiguration<>();

    conf.setName(null);
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      conf.setName("name");
    });

    conf.setDefaultConfigRef(null);
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      conf.setDefaultConfigRef("ref");
    });

    conf.setDefaultConfig(null);
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      conf.setDefaultConfig(conf);
    });
  }

  @Test
  public void testFactory() {
    final BeanReferenceHandlerConfiguration<DummyHandler> conf = new BeanReferenceHandlerConfiguration<>();

    final HandlerFactoryRegistry registry = new HandlerFactoryRegistry();
    final HandlerFactory<DummyHandler> handler = registry.getFactory(conf.getFactoryClass(), DummyHandler.class);

    Assertions.assertNotNull(handler);
    Assertions.assertEquals(BeanReferenceHandlerConfiguration.BeanReferenceHandlerFactory.class, handler.getClass());

    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      handler.create(conf);
    });

  }

  public static class DummyHandler extends AbstractSignServiceHandler {
  }

}
