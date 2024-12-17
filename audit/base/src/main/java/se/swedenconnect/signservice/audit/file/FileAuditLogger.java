/*
 * Copyright 2022-2024 Sweden Connect
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

import java.io.IOException;
import java.nio.file.Path;
import java.util.logging.Level;
import java.util.logging.Logger;

import jakarta.annotation.Nonnull;
import jakarta.annotation.PreDestroy;
import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditLoggerException;
import se.swedenconnect.signservice.audit.base.AbstractAuditLogger;

/**
 * A simple file logger that uses Java's util logging package to audit log. The logger is "rolling" and a new log file
 * is created per day.
 * <p>
 * Also see {@link se.swedenconnect.signservice.audit.logsystem.LogSystemAuditLogger} for an audit logger that can be
 * configured using an underlying log system.
 * </p>
 */
public class FileAuditLogger extends AbstractAuditLogger {

  /** Logger. */
  private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(FileAuditLogger.class);

  /** The underlying JUL handler. */
  private final DateRollingFileHandler handler;

  /** The JUL logger. */
  private final Logger auditLogger;

  /**
   * Constructor setting up the file audit logger with the target file.
   *
   * @param logFile the log file including its path
   * @throws IOException if the supplied file is not a valid file, or if it is not possible to create the file
   */
  public FileAuditLogger(@Nonnull final String logFile) throws IOException {
    this.handler = new DateRollingFileHandler(logFile);

    // Build the logger name based on the log file name ...
    final String loggerName = Path.of(logFile).toAbsolutePath().toString();

    this.auditLogger = Logger.getLogger(loggerName);
    this.auditLogger.setLevel(Level.INFO);
    this.auditLogger.addHandler(this.handler);
    this.auditLogger.setUseParentHandlers(false);
  }

  /**
   * Should be called when the object is no longer needed. The method is annotated with {@code PreDestroy} meaning that
   * the method will be automatically be invoked by frameworks supporting this annotation.
   */
  @PreDestroy
  public void close() {
    if (this.handler != null) {
      this.handler.flush();
      this.handler.close();
    }
  }

  /** {@inheritDoc} */
  @Override
  public void auditLog(@Nonnull final AuditEvent event) throws AuditLoggerException {
    if (event == null) {
      throw new AuditLoggerException("event must not be null");
    }
    try {
      log.debug("Audit logger '{}' publishing audit event '{}'", this.getName(), event.getId());
      this.auditLogger.log(Level.INFO, this.formatAuditEvent(event));
    }
    catch (final Throwable t) {
      final String msg = String.format("Audit logger '%s' failed to publish audit event - %s",
          this.getName(), t.getMessage());
      log.error("{}", msg, t);
      throw new AuditLoggerException(msg, t);
    }
  }

}
