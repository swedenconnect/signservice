/*
 * Copyright 2022-2023 Sweden Connect
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
package se.swedenconnect.signservice.audit.base;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Field;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.AuditLoggerException;
import se.swedenconnect.signservice.audit.base.events.AuditEventFactory;
import se.swedenconnect.signservice.audit.base.events.DefaultAuditEventFactory;
import se.swedenconnect.signservice.audit.base.events.SignServiceAuditEvent;
import se.swedenconnect.signservice.core.config.AbstractHandlerConfiguration;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Test cases for AbstractAuditLoggerFactory.
 */
public class AbstractAuditLoggerFactoryTest {

  @Test
  public void testNullConfig() throws Exception {
    final TestAuditLoggerFactory factory = new TestAuditLoggerFactory();
    final AuditLogger logger = factory.create(null);
    Assertions.assertNotNull(logger);
    Assertions.assertTrue(TestAuditLogger.class.isInstance(logger));

    // Assert that the default event factory is null (until it is used) ...
    final Field eventFactoryField = AbstractAuditLogger.class.getDeclaredField("eventFactory");
    eventFactoryField.setAccessible(true);
    final AuditEventFactory eventFactory = (AuditEventFactory) eventFactoryField.get(logger);
    Assertions.assertNull(eventFactory);
  }

  @Test
  public void testWithConfig() throws Exception {
    final TestAuditLoggerConfiguration config = new TestAuditLoggerConfiguration();
    config.setName("AUDIT_LOGGER_HANDLER");
    config.setEventFactory(DefaultAuditEventFactory.class);
    config.setPrincipal("client");

    final TestAuditLoggerFactory factory = new TestAuditLoggerFactory();
    final AuditLogger logger = factory.create(config);

    Assertions.assertNotNull(logger);
    Assertions.assertTrue(TestAuditLogger.class.isInstance(logger));

    Assertions.assertEquals("AUDIT_LOGGER_HANDLER", logger.getName());

    // Assert that the default event factory has been assigned
    final Field eventFactoryField = AbstractAuditLogger.class.getDeclaredField("eventFactory");
    eventFactoryField.setAccessible(true);
    final AuditEventFactory eventFactory = (AuditEventFactory) eventFactoryField.get(logger);
    Assertions.assertNotNull(eventFactory);
    Assertions.assertTrue(DefaultAuditEventFactory.class.isInstance(eventFactory));

    // Assert that the default principal was assigned
    final AuditEvent event = logger.createAuditEvent("ID");
    Assertions.assertEquals("client", event.getPrincipal());
  }

  @Test
  public void testWithConfigNoEventFactory() throws Exception {
    final TestAuditLoggerConfiguration config = new TestAuditLoggerConfiguration();
    config.setName("AUDIT_LOGGER_HANDLER");

    final TestAuditLoggerFactory factory = new TestAuditLoggerFactory();
    final AuditLogger logger = factory.create(config);

    Assertions.assertNotNull(logger);
    Assertions.assertTrue(TestAuditLogger.class.isInstance(logger));

    Assertions.assertEquals("AUDIT_LOGGER_HANDLER", logger.getName());

    // Assert that the default event factory is null (until it is used) ...
    final Field eventFactoryField = AbstractAuditLogger.class.getDeclaredField("eventFactory");
    eventFactoryField.setAccessible(true);
    final AuditEventFactory eventFactory = (AuditEventFactory) eventFactoryField.get(logger);
    Assertions.assertNull(eventFactory);
  }

  @Test
  public void testWithUnknownConfig() {
    final TestAuditLoggerFactory factory = new TestAuditLoggerFactory();
    final HandlerConfiguration<AuditLogger> conf = new AbstractHandlerConfiguration<AuditLogger>() {

      @Override
      protected String getDefaultFactoryClass() {
        return "theclass";
      }
    };
    assertThatThrownBy(() -> {
      factory.create(conf);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unknown configuration object supplied - ");

  }

  @Test
  public void testWithBadEventFactory() {
    final TestAuditLoggerConfiguration config = new TestAuditLoggerConfiguration();
    config.setEventFactory(DummyAuditEventFactory.class);

    final TestAuditLoggerFactory factory = new TestAuditLoggerFactory();
    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("No no-arg constructor visible for ");
  }

  @Test
  public void testHandlerType() {
    final TestAuditLoggerFactory f = new TestAuditLoggerFactory();
    Assertions.assertEquals(AuditLogger.class, f.handlerType());
  }

  public static class DummyAuditEventFactory implements AuditEventFactory {

    public DummyAuditEventFactory(final String s) {
    }

    @Override
    @Nonnull
    public AuditEvent createAuditEvent(@Nonnull final String eventId) {
      return new SignServiceAuditEvent(eventId);
    }

  }

  // For testing
  public static class TestAuditLoggerFactory extends AbstractAuditLoggerFactory {

    @Override
    @Nonnull
    protected AbstractAuditLogger createAuditLogger(
        @Nullable final HandlerConfiguration<AuditLogger> configuration, @Nullable final BeanLoader beanLoader)
        throws IllegalArgumentException {
      return new TestAuditLogger();
    }

    public Class<AuditLogger> handlerType() {
      return super.getHandlerType();
    }

  }

  // For testing
  public static class TestAuditLogger extends AbstractAuditLogger {

    @Override
    public void auditLog(@Nonnull final AuditEvent event) throws AuditLoggerException {
    }

  }

  // For testing
  public static class TestAuditLoggerConfiguration extends AbstractAuditLoggerConfiguration {

    @Override
    @Nonnull
    protected String getDefaultFactoryClass() {
      return TestAuditLoggerFactory.class.getName();
    }

  }

}
