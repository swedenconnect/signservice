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
package se.swedenconnect.signservice.audit.base;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditEventBuilder;
import se.swedenconnect.signservice.audit.AuditEventParameter;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.base.events.AuditEventFactory;
import se.swedenconnect.signservice.audit.base.events.DefaultAuditEventFactory;
import se.swedenconnect.signservice.core.AbstractSignServiceHandler;

/**
 * Abstract base class for {@link AuditLogger} implementations.
 */
public abstract class AbstractAuditLogger extends AbstractSignServiceHandler implements AuditLogger {

  /** The audit event factory this instance should use when creating audit event objects. */
  private AuditEventFactory eventFactory;

  /** The default principal name to assign to events. */
  private String defaultPrincipal;

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public AuditEvent createAuditEvent(@Nonnull final String eventId) {
    final AuditEvent event = this.getEventFactory().createAuditEvent(eventId);
    if (this.defaultPrincipal != null) {
      event.setPrincipal(this.defaultPrincipal);
    }
    return event;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public AuditEventBuilder getAuditEventBuilder(@Nonnull final String eventId) {
    final AuditEvent event = this.createAuditEvent(eventId);
    return new AuditEventBuilder() {

      @Override
      @Nonnull
      public AuditEvent build() {
        return event;
      }

      @Override
      @Nonnull
      public AuditEventBuilder principal(@Nonnull final String principal) {
        event.setPrincipal(principal);
        return this;
      }

      @Override
      @Nonnull
      public AuditEventBuilder parameter(@Nonnull final AuditEventParameter parameter) {
        event.addParameter(parameter);
        return this;
      }

      @Override
      @Nonnull
      public AuditEventBuilder parameter(@Nonnull final String name, @Nullable final String value) {
        event.addParameter(name, value);
        return this;
      }

    };
  }

  /**
   * Formats the supplied audit event. The default implementation invokes {@link AuditEvent#toString()}.
   *
   * @param event the event to be formatted
   * @return the string representation of the audit event
   */
  @Nonnull
  protected String formatAuditEvent(@Nonnull final AuditEvent event) {
    return event.toString();
  }

  /**
   * Assigns the event factory to use. If no factory is assigned, {@link DefaultAuditEventFactory} is used.
   *
   * @param eventFactory the event factory
   */
  public void setEventFactory(@Nonnull final AuditEventFactory eventFactory) {
    this.eventFactory = eventFactory;
  }

  /**
   * Gets the audit event factory to use.
   *
   * @return the event factory
   */
  @Nonnull
  protected synchronized AuditEventFactory getEventFactory() {
    if (this.eventFactory == null) {
      this.eventFactory = new DefaultAuditEventFactory();
    }
    return this.eventFactory;
  }

  /**
   * Assigns the default principal name to assign to events.
   *
   * @param defaultPrincipal the principal to use.
   */
  public void setDefaultPrincipal(@Nonnull final String defaultPrincipal) {
    this.defaultPrincipal = defaultPrincipal;
  }

}
