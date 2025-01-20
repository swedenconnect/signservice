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
package se.swedenconnect.signservice.audit.callback;

import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.Nonnull;
import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.AuditLoggerException;
import se.swedenconnect.signservice.audit.base.AbstractAuditLogger;

/**
 * An {@link AuditLogger} implementation that will hand over all events to the configured {@link AuditLoggerListener}.
 */
public class CallbackAuditLogger extends AbstractAuditLogger {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(CallbackAuditLogger.class);

  /** The audit logger listener. */
  private final AuditLoggerListener listener;

  /**
   * Constructor.
   *
   * @param listener the audit logger listener
   */
  public CallbackAuditLogger(@Nonnull final AuditLoggerListener listener) {
    this.listener = Objects.requireNonNull(listener, "listener must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public void auditLog(@Nonnull final AuditEvent event) throws AuditLoggerException {
    if (event == null) {
      throw new AuditLoggerException("event must not be null");
    }
    try {
      log.debug("Audit logger '{}' publishing audit event '{}'", this.getName(), event.getId());
      this.listener.onAuditEvent(event);
    }
    catch (final Throwable t) {
      final String msg = String.format("Failed to publish audit event - %s", t.getMessage());
      throw new AuditLoggerException(msg, t);
    }
  }

}
