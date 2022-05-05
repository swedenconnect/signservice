package se.swedenconnect.signservice.audit.base.events;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.swedenconnect.signservice.audit.AuditEvent;

public class AuditEventFactoryTest {

  @Test
  public void testCreateAuditEventWithId() {
    final AuditEvent event = AuditEventFactory.createAuditEvent("id");
    Assertions.assertEquals("id", event.getId());
    Assertions.assertEquals(AuditEventFactory.DEFAULT_PRINCIPAL, event.getPrincipal());
  }

  @Test
  public void testCreateAuditEvent() {
    final AuditEvent event = AuditEventFactory.createAuditEvent("id", "principal");
    Assertions.assertEquals("id", event.getId());
    Assertions.assertEquals("principal", event.getPrincipal());
  }

}