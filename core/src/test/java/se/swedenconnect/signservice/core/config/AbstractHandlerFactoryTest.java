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
import javax.annotation.Nullable;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.core.AbstractSignServiceHandler;

/**
 * Tests for AbstractHandlerFactory.
 */
public class AbstractHandlerFactoryTest {

  @Test
  public void testCreateNoBeanLoader() {
    final DummyHandlerFactory factory = new DummyHandlerFactory();
    final DummyHandlerConfiguration conf = new DummyHandlerConfiguration();

    final DummyHandler handler = factory.create(conf);
    Assertions.assertNotNull(handler);
  }

  @Test
  public void testCreateNoConf() {
    final DummyHandlerFactory factory = new DummyHandlerFactory();

    final DummyHandler handler = factory.create(null);
    Assertions.assertNotNull(handler);
  }

  @Test
  public void testNotResolved() {
    final DummyHandlerFactory factory = new DummyHandlerFactory();
    final DummyHandlerConfiguration conf = new DummyHandlerConfiguration();
    conf.setDefaultConfigRef("ref");

    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      factory.create(conf);
    });
  }

  @Test
  public void testMissingBeanLoader() {
    final DummyHandlerFactory factory = new DummyHandlerFactory();
    final DummyHandlerConfiguration conf = new DummyHandlerConfiguration();
    conf.setBeanName("bean.name");

    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      factory.create(conf, null);
    });
  }

  @Test
  public void testCreateWithBeanLoader() {
    final DummyHandler handler = new DummyHandler();
    final DummyHandlerFactory factory = new DummyHandlerFactory();
    final DummyHandlerConfiguration conf = new DummyHandlerConfiguration();
    conf.setBeanName("bean.name");

    final DummyHandler handler2 = factory.create(conf, (ref) -> handler);
    Assertions.assertEquals(handler, handler2);
  }



  public static class DummyHandler extends AbstractSignServiceHandler {
  }

  public static class DummyHandlerFactory extends AbstractHandlerFactory<DummyHandler> {

    @Override
    @Nonnull
    protected DummyHandler createHandler(@Nullable final HandlerConfiguration<DummyHandler> configuration)
        throws IllegalArgumentException {
      return new DummyHandler();
    }
  }

  public static class DummyHandlerConfiguration extends AbstractHandlerConfiguration<DummyHandler> {

    @Override
    @Nonnull
    protected String getDefaultFactoryClass() {
      return DummyHandlerFactory.class.getName();
    }

  }

}
