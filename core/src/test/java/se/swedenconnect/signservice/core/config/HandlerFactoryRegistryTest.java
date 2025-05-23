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
package se.swedenconnect.signservice.core.config;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.core.AbstractSignServiceHandler;

/**
 * Tests of HandlerFactoryRegistry.
 */
public class HandlerFactoryRegistryTest {

  @Test
  public void testCreate() {
    final HandlerFactoryRegistry reg = new HandlerFactoryRegistry();
    final HandlerFactory<DummyHandler> factory = reg.getFactory(DummyHandlerFactory.class.getName());
    Assertions.assertNotNull(factory);
    Assertions.assertEquals(DummyHandlerFactory.class, factory.getClass());

    // Make sure a cache is used ...
    final HandlerFactory<DummyHandler> factory2 = reg.getFactory(DummyHandlerFactory.class.getName());
    Assertions.assertEquals(factory, factory2);
  }

  @Test
  public void testMissingClass() {
    final HandlerFactoryRegistry reg = new HandlerFactoryRegistry();
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      reg.getFactory("se.swedenconnect.NotAClass");
    });
  }

  @Test
  public void testNoNoArgCtor() {
    final HandlerFactoryRegistry reg = new HandlerFactoryRegistry();
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      reg.getFactory(DummyHandlerFactoryNoDefaultCtor.class.getName());
    });
  }

  @Test
  public void testAddAndUseCached() {
    final HandlerFactoryRegistry reg = new HandlerFactoryRegistry();
    final DummyHandlerFactory factory = new DummyHandlerFactory();
    reg.addFactory(factory);

    // Make sure a cache is used ...
    final HandlerFactory<DummyHandler> factory2 = reg.getFactory(DummyHandlerFactory.class.getName());
    Assertions.assertEquals(factory, factory2);
  }

  public static class DummyHandler extends AbstractSignServiceHandler {
  }

  public static class DummyHandlerFactory extends AbstractHandlerFactory<DummyHandler> {

    @Override
    @Nonnull
    protected DummyHandler createHandler(
        @Nullable final HandlerConfiguration<DummyHandler> configuration, @Nonnull final BeanLoader beanLoader)
        throws IllegalArgumentException {
      return new DummyHandler();
    }

    @Override
    protected Class<DummyHandler> getHandlerType() {
      return DummyHandler.class;
    }
  }

  public static class DummyHandlerFactoryNoDefaultCtor extends AbstractHandlerFactory<DummyHandler> {

    public DummyHandlerFactoryNoDefaultCtor(final String arg) {
    }

    @Override
    @Nonnull
    protected DummyHandler createHandler(
        @Nullable final HandlerConfiguration<DummyHandler> configuration, @Nonnull final BeanLoader beanLoader)
        throws IllegalArgumentException {
      return new DummyHandler();
    }

    @Override
    protected Class<DummyHandler> getHandlerType() {
      return DummyHandler.class;
    }
  }
}
