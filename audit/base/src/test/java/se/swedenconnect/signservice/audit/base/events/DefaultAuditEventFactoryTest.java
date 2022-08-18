package se.swedenconnect.signservice.audit.base.events;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.audit.AuditEvent;

/**
 * Test cases for DefaultAuditEventFactory.
 */
public class DefaultAuditEventFactoryTest {

  @Test
  public void testCreateAuditEvent() {
    final DefaultAuditEventFactory factory = new DefaultAuditEventFactory();
    final AuditEvent event = factory.createAuditEvent("id");
    Assertions.assertEquals("id", event.getId());
  }

}