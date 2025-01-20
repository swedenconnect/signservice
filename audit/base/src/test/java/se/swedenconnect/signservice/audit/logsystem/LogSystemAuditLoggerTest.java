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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditLoggerException;
import se.swedenconnect.signservice.audit.MemoryAppender;
import se.swedenconnect.signservice.audit.base.events.DefaultAuditEventFactory;

/**
 * Test cases for LogSystemAuditLogger.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class LogSystemAuditLoggerTest {

  private static final String LOGGER_NAME = "testlogger";

  private MemoryAppender memoryAppender;

  private MemoryAppender memoryAppenderDebug;

  @BeforeAll
  public void setup() {
    this.memoryAppender = new MemoryAppender();
    this.memoryAppender.setContext((LoggerContext) LoggerFactory.getILoggerFactory());

    this.memoryAppenderDebug = new MemoryAppender();
    this.memoryAppenderDebug.setContext((LoggerContext) LoggerFactory.getILoggerFactory());

    final Logger auditLogger = (Logger) LoggerFactory.getLogger(LOGGER_NAME);
    auditLogger.setLevel(Level.INFO);
    auditLogger.addAppender(this.memoryAppender);

    final Logger logger = (Logger) LoggerFactory.getLogger(LogSystemAuditLogger.class);
    logger.setLevel(Level.DEBUG);
    logger.addAppender(this.memoryAppenderDebug);

    this.memoryAppender.start();
    this.memoryAppenderDebug.start();
  }

  @Test
  public void testAuditLog() {
    this.memoryAppenderDebug.reset();

    final LogSystemAuditLogger auditLogger = new LogSystemAuditLogger(LOGGER_NAME);
    auditLogger.setEventFactory(new DefaultAuditEventFactory());

    final AuditEvent event = auditLogger.createAuditEvent("ID");
    event.addParameter("parameter", "value");
    auditLogger.auditLog(event);

    assertThat(this.memoryAppenderDebug.search(Level.DEBUG))
        .hasSize(1)
        .extracting(ILoggingEvent::toString)
        .anySatisfy(message -> assertThat(message).contains(
            String.format("Audit logger '%s' ('%s') publishing audit event 'ID'",
                LogSystemAuditLogger.class.getSimpleName(), LOGGER_NAME)));

    final String eventString = event.toString();

    assertThat(this.memoryAppender.search(Level.INFO))
        .hasSize(1)
        .extracting(ILoggingEvent::toString)
        .anySatisfy(message -> assertThat(message).contains(eventString));
  }

  @Test
  public void testAuditLogLoggingThrows() {
    final LogSystemAuditLogger auditLogger = new LogSystemAuditLogger(LOGGER_NAME);
    auditLogger.setEventFactory(new DefaultAuditEventFactory());

    final AuditEvent event = Mockito.mock(AuditEvent.class);
    Mockito.when(event.getId()).thenReturn("ID");
    Mockito.when(event.toString()).thenThrow(IllegalArgumentException.class);

    Assertions.assertThrows(AuditLoggerException.class, () -> {
      auditLogger.auditLog(event);
    });
  }

  @Test
  public void testBadLoggerName() {
    assertThatThrownBy(() -> {
      new LogSystemAuditLogger(null);
    }).isInstanceOf(NullPointerException.class)
        .hasMessageContaining("loggerName must not be null or empty");
    assertThatThrownBy(() -> {
      new LogSystemAuditLogger("");
    }).isInstanceOf(NullPointerException.class)
        .hasMessageContaining("loggerName must not be null or empty");
  }

  @Test
  public void testAuditLogNullEvent() {
    final LogSystemAuditLogger auditLogger = new LogSystemAuditLogger(LOGGER_NAME);
    assertThatThrownBy(() -> {
      auditLogger.auditLog(null);
    }).isInstanceOf(AuditLoggerException.class)
        .hasMessageContaining("event must not be null");
  }

}
