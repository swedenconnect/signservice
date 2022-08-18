package se.swedenconnect.signservice.audit.file;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import javax.annotation.Nonnull;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.mockito.Mockito;

import ch.qos.logback.classic.spi.ILoggingEvent;
import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditLoggerException;
import se.swedenconnect.signservice.audit.MemoryAppender;
import se.swedenconnect.signservice.audit.base.events.DefaultAuditEventFactory;

/**
 * Test cases for FileAuditLogger.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class FileAuditLoggerTest {

  private static final String LOG_FILE = "target/fileaudit.log";

  private MemoryAppender memoryAppenderDebug;

  @BeforeEach
  public void setup() {
    this.memoryAppenderDebug = new MemoryAppender();
    this.memoryAppenderDebug
        .setContext((ch.qos.logback.classic.LoggerContext) org.slf4j.LoggerFactory.getILoggerFactory());

    final ch.qos.logback.classic.Logger logger =
        (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(FileAuditLogger.class);
    logger.setLevel(ch.qos.logback.classic.Level.DEBUG);
    logger.addAppender(this.memoryAppenderDebug);

    this.memoryAppenderDebug.start();
  }

  @AfterEach
  public void cleanup() throws Exception {
    this.memoryAppenderDebug.reset();
    this.removeLogFile(LOG_FILE);
  }

  @Test
  public void testAuditLog() throws Exception {
    final FileAuditLogger auditLogger = new FileAuditLogger(LOG_FILE);
    auditLogger.setEventFactory(new DefaultAuditEventFactory());
    auditLogger.setName("audit-logger");

    final AuditEvent event = auditLogger.createAuditEvent("ID");
    event.addParameter("parameter", "value");
    auditLogger.auditLog(event);

    assertThat(this.memoryAppenderDebug.search(ch.qos.logback.classic.Level.DEBUG))
        .hasSize(1)
        .extracting(ILoggingEvent::toString)
        .anySatisfy(message -> assertThat(message).contains(
            String.format("Audit logger '%s' publishing audit event 'ID'", auditLogger.getName())));

    auditLogger.close();

    final String eventString = event.toString();

    final Path logFile = Path.of(LOG_FILE);
    final List<String> lines = Files.readAllLines(logFile);
    Assertions.assertTrue(lines.size() == 1);
    Assertions.assertEquals(eventString, lines.get(0));
  }

  @Test
  public void auditLogLoggingThrows() throws Exception {
    final FileAuditLogger auditLogger = new FileAuditLogger(LOG_FILE);
    auditLogger.setEventFactory(new DefaultAuditEventFactory());
    auditLogger.setName("audit-logger");

    final AuditEvent event = Mockito.mock(AuditEvent.class);
    Mockito.when(event.getId()).thenReturn("ID");
    Mockito.when(event.toString()).thenThrow(IllegalArgumentException.class);

    Assertions.assertThrows(AuditLoggerException.class, () -> {
      auditLogger.auditLog(event);
    });

    auditLogger.close();
  }

  @Test
  public void testMissingLogFile() {
    assertThatThrownBy(() -> {
      new FileAuditLogger(null);
    }).isInstanceOf(NullPointerException.class)
        .hasMessageContaining("logFile must not be null");
  }

  @Test
  public void testAuditLogNullEvent() throws Exception {
    final FileAuditLogger auditLogger = new FileAuditLogger(LOG_FILE);
    assertThatThrownBy(() -> {
      auditLogger.auditLog(null);
    }).isInstanceOf(AuditLoggerException.class)
        .hasMessageContaining("event must not be null");

    auditLogger.close();
  }

  private void removeLogFile(@Nonnull final String file) throws IOException {
    final Path logFile = Path.of(file);
    Files.deleteIfExists(logFile);
  }
}