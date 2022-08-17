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

import java.util.Map;
import java.util.stream.Collectors;

import javax.annotation.Nonnull;

import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditEventParameter;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.AuditLoggerException;
import se.swedenconnect.signservice.audit.base.AbstractAuditLogger;

/**
 * An {@link AuditLogger} Spring actuator implementation.
 */
@Slf4j
public class ActuatorAuditLogger extends AbstractAuditLogger implements ApplicationEventPublisherAware {

  /** The ApplicationEventPublisher used to publish events. */
  private ApplicationEventPublisher publisher;

  /** {@inheritDoc} */
  @Override
  public void auditLog(@Nonnull final AuditEvent event) throws AuditLoggerException {
    if (event == null) {
      throw new AuditLoggerException("event must not be null");
    }
    try {
      log.debug("Audit logger '{}' publishing audit event '{}'", this.getName(), event.getId());
      this.publisher.publishEvent(this.createActuatorEvent(event));
    }
    catch (final Throwable t) {
      final String msg = String.format("Failed to publish audit event - %s", t.getMessage());
      throw new AuditLoggerException(msg, t);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void setApplicationEventPublisher(@Nonnull final ApplicationEventPublisher publisher) {
    this.publisher = publisher;
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
