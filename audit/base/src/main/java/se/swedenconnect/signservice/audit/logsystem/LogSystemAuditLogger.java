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
package se.swedenconnect.signservice.audit.logsystem;

import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.Nonnull;
import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.AuditLoggerException;
import se.swedenconnect.signservice.audit.base.AbstractAuditLogger;

/**
 * An {@link AuditLogger} implementation that uses an underlying logsystem, via Slf4j, to produce audit log entries.
 * <p>
 * Note that the underlying logsystem must be configured with a logger name corresponding to the logger name given in
 * the {@link #LogSystemAuditLogger(String)} constructor.
 * </p>
 */
public class LogSystemAuditLogger extends AbstractAuditLogger {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(LogSystemAuditLogger.class);

  /** The logger instance. */
  private final Logger auditLogger;

  /** The logger name. */
  private final String loggerName;

  /**
   * Constructor setting up the audit logger based on the supplied logger name.
   *
   * @param loggerName the logger name
   */
  public LogSystemAuditLogger(@Nonnull final String loggerName) {
    this.loggerName = Optional.ofNullable(loggerName)
        .filter(StringUtils::isNotBlank)
        .orElseThrow(() -> new NullPointerException("loggerName must not be null or empty"));
    this.auditLogger = LoggerFactory.getLogger(this.loggerName);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public void auditLog(@Nonnull final AuditEvent event) throws AuditLoggerException {
    if (event == null) {
      throw new AuditLoggerException("event must not be null");
    }
    try {
      log.debug("Audit logger '{}' ('{}') publishing audit event '{}'",
          this.getName(), this.auditLogger.getName(), event.getId());
      final String eventString = this.formatAuditEvent(event);
      this.auditLogger.info("{}", eventString);
    }
    catch (final Throwable t) {
      final String msg = String.format("Audit logger '%s' ('%s') failed to publish audit event - %s",
          this.getName(), this.auditLogger.getName(), t.getMessage());
      log.error("{}", msg, t);
      throw new AuditLoggerException(msg, t);
    }
  }

}
