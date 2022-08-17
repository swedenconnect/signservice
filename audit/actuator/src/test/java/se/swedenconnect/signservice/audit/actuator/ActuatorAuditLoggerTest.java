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
import org.mockito.Mockito;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;

import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditLoggerException;

/**
 * Test cases for ActuatorAuditLogger.
 */
public class ActuatorAuditLoggerTest {

  @Test
  public void testAuditLog() {
    final ApplicationEventPublisher mockPublisher = mock(ApplicationEventPublisher.class);

    final ActuatorAuditLogger auditLogger = new ActuatorAuditLogger();
    auditLogger.setApplicationEventPublisher(mockPublisher);

    doNothing().when(mockPublisher).publishEvent(any(AuditApplicationEvent.class));

    final AuditEvent event = auditLogger.createAuditEvent("id");
    event.setPrincipal("principal");
    event.addParameter("param1", "value1");

    auditLogger.auditLog(event);

    verify(mockPublisher, times(1))
        .publishEvent(any(AuditApplicationEvent.class));

    final ArgumentCaptor<AuditApplicationEvent> eventArgumentCaptor =
        ArgumentCaptor.forClass(AuditApplicationEvent.class);

    verify(mockPublisher).publishEvent(eventArgumentCaptor.capture());

    final org.springframework.boot.actuate.audit.AuditEvent actualEvent =
        eventArgumentCaptor.getValue().getAuditEvent();

    assertThat(actualEvent.getType()).isEqualTo("id");
    assertThat(actualEvent.getPrincipal()).isEqualTo("principal");
    assertThat(actualEvent.getData()).containsEntry("param1", "value1");
  }

  @Test
  public void testAuditLogError() {
    final ApplicationEventPublisher mockPublisher = mock(ApplicationEventPublisher.class);

    final ActuatorAuditLogger auditLogger = new ActuatorAuditLogger();
    auditLogger.setApplicationEventPublisher(mockPublisher);

    Mockito.doThrow(IllegalArgumentException.class).when(mockPublisher).publishEvent(any(AuditApplicationEvent.class));

    final AuditEvent event = auditLogger.createAuditEvent("id");
    event.setPrincipal("principal");
    event.addParameter("param1", "value1");

    assertThatThrownBy(() -> {
      auditLogger.auditLog(event);
    }).isInstanceOf(AuditLoggerException.class)
        .hasMessageContaining("Failed to publish audit event -");

    final ActuatorAuditLogger auditLogger2 = new ActuatorAuditLogger();

    assertThatThrownBy(() -> {
      auditLogger2.auditLog(event);
    }).isInstanceOf(AuditLoggerException.class)
        .getCause()
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  public void testAuditLogNullEvent() {
    final ActuatorAuditLogger auditLogger = new ActuatorAuditLogger();
    assertThatThrownBy(() -> {
      auditLogger.auditLog(null);
    }).isInstanceOf(AuditLoggerException.class)
        .hasMessage("event must not be null");
  }

}