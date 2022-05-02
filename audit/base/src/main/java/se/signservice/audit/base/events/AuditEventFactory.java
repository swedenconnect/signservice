package se.signservice.audit.base.events;

import se.swedenconnect.signservice.audit.AuditEvent;

public class AuditEventFactory {

  public final static String DEFAULT_PRINCIPAL = "SignService";

  public static AuditEvent createAuditEvent(final String eventId) {
    return new SignServiceAuditEvent(eventId, DEFAULT_PRINCIPAL);
  }

  public static AuditEvent createAuditEvent(final String eventId, final String principal) {
    return new SignServiceAuditEvent(eventId, principal);
  }

  private AuditEventFactory() {}
}
