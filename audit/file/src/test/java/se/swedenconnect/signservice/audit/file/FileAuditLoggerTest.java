package se.swedenconnect.signservice.audit.file;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.LoggerFactory;
import se.signservice.audit.base.events.AuditEventFactory;
import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditLoggerException;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FileAuditLoggerTest {

  private MemoryAppender memoryAppender;

  @BeforeAll
  void setup() {
    memoryAppender = new MemoryAppender();
    memoryAppender.setContext((LoggerContext) LoggerFactory.getILoggerFactory());

    final Logger auditLogger = (Logger) LoggerFactory.getLogger(FileAuditLogger.AUDIT_LOG);
    auditLogger.setLevel(Level.INFO);
    auditLogger.addAppender(memoryAppender);

    final Logger logger = (Logger) LoggerFactory.getLogger(FileAuditLogger.class);
    logger.setLevel(Level.DEBUG);
    logger.addAppender(memoryAppender);

    memoryAppender.start();
  }

  @Test
  void auditLog() {
    final FileAuditLogger auditLogger = new FileAuditLogger();

    final AuditEvent event = AuditEventFactory.createAuditEvent("id");
    auditLogger.auditLog(event);

    assertThat(memoryAppender.search(Level.DEBUG))
      .hasSize(1)
      .extracting(ILoggingEvent::toString)
      .anySatisfy(message -> assertThat(message).contains("Publish audit event [id]"));

    assertThat(memoryAppender.search(Level.INFO))
      .hasSize(1)
      .extracting(ILoggingEvent::toString)
      .anySatisfy(message -> assertThat(message).contains("AuditEvent"));
  }

  @Test
  void testAuditLog_whenEventIsNull_throwException() {
    final FileAuditLogger auditLogger = new FileAuditLogger();
    assertThatThrownBy(() -> {
      auditLogger.auditLog(null);
    }).isInstanceOf(AuditLoggerException.class)
      .hasMessageContaining("event must not be null");
  }

  //TODO: Refactor to TestUtils?
  public class MemoryAppender extends ListAppender<ILoggingEvent> {

    public void reset() {
      this.list.clear();
    }

    public boolean contains(String string, Level level) {
      return this.list.stream()
        .anyMatch(event -> event.toString().contains(string)
          && event.getLevel().equals(level));
    }

    public int countEventsForLogger(String loggerName) {
      return (int) this.list.stream()
        .filter(event -> event.getLoggerName().contains(loggerName))
        .count();
    }

    public List<ILoggingEvent> search(String string) {
      return this.list.stream()
        .filter(event -> event.toString().contains(string))
        .collect(Collectors.toList());
    }

    public List<ILoggingEvent> search(String string, Level level) {
      return this.list.stream()
        .filter(event -> event.toString().contains(string)
          && event.getLevel().equals(level))
        .collect(Collectors.toList());
    }

    public List<ILoggingEvent> search(Level level) {
      return this.list.stream()
        .filter(event -> event.getLevel().equals(level))
        .collect(Collectors.toList());
    }

    public int getSize() {
      return this.list.size();
    }

    public List<ILoggingEvent> getLoggedEvents() {
      return Collections.unmodifiableList(this.list);
    }
  }
}