/*
 * Copyright 2022-2023 Sweden Connect
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

import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;

import jakarta.annotation.Nonnull;
import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditEventParameter;
import se.swedenconnect.signservice.audit.callback.AuditLoggerListener;

/**
 * An {@link AuditLoggerListener} for logging to a Spring {@link ApplicationEventPublisher}.
 */
public class ActuatorAuditLoggerListener implements AuditLoggerListener {

  private final ApplicationEventPublisher publisher;

  /**
   * Constructor assigning the {@link ApplicationEventPublisher} to publish audit events to.
   *
   * @param publisher the event publisher
   */
  public ActuatorAuditLoggerListener(@Nonnull final ApplicationEventPublisher publisher) {
    this.publisher = Objects.requireNonNull(publisher, "publisher must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public void onAuditEvent(@Nonnull final AuditEvent event) {
    this.publisher.publishEvent(this.createActuatorEvent(event));
  }

  /**
   * Creates and actuates audit event.
   *
   * @param event the SignService AuditEvent
   * @return the audit event
   */
  @Nonnull
  protected AuditApplicationEvent createActuatorEvent(@Nonnull final AuditEvent event) {
    final Map<String, Object> auditParameters = event.getParameters().stream()
        .collect(Collectors.toMap(AuditEventParameter::getName, AuditEventParameter::getValue));

    return new AuditApplicationEvent(
        new org.springframework.boot.actuate.audit.AuditEvent(
            event.getTimestamp(), event.getPrincipal(), event.getId(), auditParameters));
  }

}
