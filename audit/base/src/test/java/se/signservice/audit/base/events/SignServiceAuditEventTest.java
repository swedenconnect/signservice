package se.signservice.audit.base.events;

import org.junit.jupiter.api.Test;
import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditEventIds;

import static org.junit.jupiter.api.Assertions.*;

class SignServiceAuditEventTest {

  @Test
  void testToString() {
    AuditEvent event = AuditEventFactory.createAuditEvent(AuditEventIds.EVENT_SYSTEM_STARTED);
    event.addParameter("param1", "1");
    event.addParameter("param2", "2");
    System.out.println(event);
  }
}