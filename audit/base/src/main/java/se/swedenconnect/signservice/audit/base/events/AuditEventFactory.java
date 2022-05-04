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
package se.swedenconnect.signservice.audit.base.events;

import se.swedenconnect.signservice.audit.AuditEvent;

/**
 * A factory for audit events
 */
public class AuditEventFactory {

  /** The default principal */
  public final static String DEFAULT_PRINCIPAL = "SignService";

  /**
   * Creates an audit event
   * @param eventId the event id
   * @return the audit event
   */
  public static AuditEvent createAuditEvent(final String eventId) {
    return new SignServiceAuditEvent(eventId, DEFAULT_PRINCIPAL);
  }

  /**
   * Creates an audit event
   * @param eventId   the event id
   * @param principal the event principal
   * @return the audit event
   */
  public static AuditEvent createAuditEvent(final String eventId, final String principal) {
    return new SignServiceAuditEvent(eventId, principal);
  }

  // Private constructor
  private AuditEventFactory() {}
}
