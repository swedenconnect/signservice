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

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Component;
import se.signservice.audit.base.events.AuditEventFactory;
import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditEventParameter;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.AuditLoggerException;

import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * The {@link AuditLogger} implementation for spring actuator
 */
@Slf4j
@Component
public class ActuatorAuditLogger implements AuditLogger, ApplicationEventPublisherAware {

  /** The ApplicationEventPublisher used to publish events */
  private ApplicationEventPublisher publisher;

  /** {@inheritDoc} */
  @Override
  public void auditLog(final AuditEvent event) throws AuditLoggerException {
    Objects.requireNonNull(event, "event must not be null");
    log.info("Publish audit event [{}]", event.getId());
    publisher.publishEvent(createActuatorEvent(event));
  }

  /** {@inheritDoc} */
  @Override
  public AuditEvent createAuditEvent(final String eventId) {
    return AuditEventFactory.createAuditEvent(eventId);
  }

  /** {@inheritDoc}*/
  @Override
  public void setApplicationEventPublisher(@NonNull final ApplicationEventPublisher publisher) {
    this.publisher = publisher;
  }

  /**
   * Creates and actuate audit event
   * @param event - The SignService AuditEvent
   * @return - An Actuator Audit Event
   */
  protected org.springframework.boot.actuate.audit.AuditEvent createActuatorEvent(final AuditEvent event) {
    Objects.requireNonNull(event, "event must not be null");
    final Map<String, Object> auditParameters = event.getParameters().stream()
      .collect(Collectors.toMap(AuditEventParameter::getName, AuditEventParameter::getValue));
    return new org.springframework.boot.actuate.audit.AuditEvent(event.getPrincipal(), event.getId(), auditParameters);
  }

}
