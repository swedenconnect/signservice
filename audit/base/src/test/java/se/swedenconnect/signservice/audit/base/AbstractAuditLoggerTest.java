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
package se.swedenconnect.signservice.audit.base;

import java.lang.reflect.Field;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import jakarta.annotation.Nonnull;
import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditEventParameter;
import se.swedenconnect.signservice.audit.AuditLoggerException;
import se.swedenconnect.signservice.audit.base.events.AuditEventFactory;
import se.swedenconnect.signservice.audit.base.events.DefaultAuditEventFactory;

/**
 * Test cases for AbstractAuditLogger.
 */
public class AbstractAuditLoggerTest {

  @Test
  public void testInit() throws Exception {
    final TestAuditLogger auditLogger = new TestAuditLogger();

    // Assert that the default event factory is null (until it is used) ...
    final Field eventFactoryField = AbstractAuditLogger.class.getDeclaredField("eventFactory");
    eventFactoryField.setAccessible(true);
    AuditEventFactory eventFactory = (AuditEventFactory) eventFactoryField.get(auditLogger);
    Assertions.assertNull(eventFactory);

    auditLogger.createAuditEvent("ID");

    // Now it should be set ...
    eventFactory = (AuditEventFactory) eventFactoryField.get(auditLogger);
    Assertions.assertNotNull(eventFactory);
    Assertions.assertTrue(DefaultAuditEventFactory.class.isInstance(eventFactory));
  }

  @Test
  public void testInitSetFactory() throws Exception {
    final TestAuditLogger auditLogger = new TestAuditLogger();
    auditLogger.setEventFactory(new DefaultAuditEventFactory());

    // Assert that the factory is set
    final Field eventFactoryField = AbstractAuditLogger.class.getDeclaredField("eventFactory");
    eventFactoryField.setAccessible(true);
    final AuditEventFactory eventFactory = (AuditEventFactory) eventFactoryField.get(auditLogger);
    Assertions.assertNotNull(eventFactory);
    Assertions.assertTrue(DefaultAuditEventFactory.class.isInstance(eventFactory));

    Assertions.assertNotNull(auditLogger.createAuditEvent("ID"));
  }

  @Test
  public void testDefaultPrincipal() throws Exception {
    final TestAuditLogger auditLogger = new TestAuditLogger();
    auditLogger.setDefaultPrincipal("client");
    auditLogger.setEventFactory(new DefaultAuditEventFactory());

    final AuditEvent event = auditLogger.createAuditEvent("ID");
    Assertions.assertEquals("client", event.getPrincipal());
  }

  @Test
  public void testBuilder() throws Exception {
    final TestAuditLogger auditLogger = new TestAuditLogger();
    auditLogger.setEventFactory(new DefaultAuditEventFactory());

    final AuditEvent event = auditLogger.getAuditEventBuilder("ID")
        .principal("client")
        .parameter("param1", "value1")
        .parameter(new AuditEventParameter("param2", "value2"))
        .build();
    Assertions.assertEquals("ID", event.getId());
    Assertions.assertEquals("client", event.getPrincipal());
    Assertions.assertEquals("value1", event.getParameters().stream().filter(p -> "param1".equals(p.getName()))
        .map(AuditEventParameter::getValue).findFirst().orElse(null));
    Assertions.assertEquals("value2", event.getParameters().stream().filter(p -> "param2".equals(p.getName()))
        .map(AuditEventParameter::getValue).findFirst().orElse(null));
    Assertions.assertEquals(2, event.getParameters().size());
    Assertions.assertNotNull(event.getTimestamp());
  }

  // For testing
  public static class TestAuditLogger extends AbstractAuditLogger {

    @Override
    public void auditLog(@Nonnull final AuditEvent event) throws AuditLoggerException {
    }

  }

}
