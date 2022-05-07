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
package se.swedenconnect.signservice.audit.file;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.swedenconnect.signservice.audit.base.events.AuditEventFactory;
import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.AuditLoggerException;

/**
 * The {@link AuditLogger} log file implementation
 */
@Slf4j
public class FileAuditLogger implements AuditLogger {

  /**
   * The audit log name
   */
  protected final static String AUDIT_LOGGER_NAME = "AUDIT_LOG";

  /**
   * The audit log
   */
  private final static Logger auditLog = LoggerFactory.getLogger(AUDIT_LOGGER_NAME);

  /**
   * {@inheritDoc}
   */
  @Override
  public void auditLog(final AuditEvent event) throws AuditLoggerException {
    if (event == null) {
      throw new AuditLoggerException("event must not be null");
    }
    try {
      log.debug("Publish audit event [{}]", event.getId());
      auditLog.info("{}", event);
    } catch (Throwable t) {
      final String msg = String.format("Couldn't publish audit event - %s", t.getMessage());
      throw new AuditLoggerException(msg, t);
    }
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public AuditEvent createAuditEvent(final String eventId) {
    return AuditEventFactory.createAuditEvent(eventId);
  }

}
