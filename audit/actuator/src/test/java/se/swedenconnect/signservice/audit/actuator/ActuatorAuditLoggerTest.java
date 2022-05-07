package se.swedenconnect.signservice.audit.actuator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;

import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditLoggerException;
import se.swedenconnect.signservice.audit.base.events.AuditEventFactory;

public class ActuatorAuditLoggerTest {

  @Test
  public void testAuditLog() {
    final ApplicationEventPublisher mockPublisher = mock(ApplicationEventPublisher.class);

    final ActuatorAuditLogger auditLogger = new ActuatorAuditLogger();
    auditLogger.setApplicationEventPublisher(mockPublisher);

    doNothing().when(mockPublisher).publishEvent(any(AuditEvent.class));

    final AuditEvent event = AuditEventFactory.createAuditEvent("id", "principal");
    event.addParameter("param1", "value1");

    auditLogger.auditLog(event);

    verify(mockPublisher, times(1))
      .publishEvent(any(org.springframework.boot.actuate.audit.AuditEvent.class));

    ArgumentCaptor<org.springframework.boot.actuate.audit.AuditEvent> eventArgumentCaptor
      = ArgumentCaptor.forClass(org.springframework.boot.actuate.audit.AuditEvent.class);

    verify(mockPublisher).publishEvent(eventArgumentCaptor.capture());

    org.springframework.boot.actuate.audit.AuditEvent actualEvent = eventArgumentCaptor.getValue();

    assertThat(actualEvent.getType()).isEqualTo("id");
    assertThat(actualEvent.getPrincipal()).isEqualTo("principal");
    assertThat(actualEvent.getData()).containsEntry("param1", "value1");

  }

  @Test
  public void testAuditLogNullEvent() {
    final ActuatorAuditLogger auditLogger = new ActuatorAuditLogger();
    assertThatThrownBy(() -> {
      auditLogger.auditLog(null);
    }).isInstanceOf(AuditLoggerException.class)
      .hasMessageContaining("event must not be null");
  }

}