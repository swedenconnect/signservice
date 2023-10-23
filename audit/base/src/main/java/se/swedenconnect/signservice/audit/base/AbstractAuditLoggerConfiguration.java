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
package se.swedenconnect.signservice.audit.base;

import java.util.Optional;

import org.apache.commons.lang3.StringUtils;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.base.events.AuditEventFactory;
import se.swedenconnect.signservice.audit.base.events.DefaultAuditEventFactory;
import se.swedenconnect.signservice.core.config.AbstractHandlerConfiguration;

/**
 * Abstract handler configuration for creating {@link AuditLogger} instances.
 */
public abstract class AbstractAuditLoggerConfiguration extends AbstractHandlerConfiguration<AuditLogger> {

  /**
   * The audit event factory class to use.
   */
  private Class<? extends AuditEventFactory> eventFactory;

  /**
   * The default principal to assign to audit events. It should be equal to the clientID that the audit logger is
   * servicing. If the audit logger is a system logger, the {@link AuditEvent#DEFAULT_PRINCIPAL} should be used.
   */
  private String principal;

  /**
   * If the default ({@link DefaultAuditEventFactory}) has been overridden (see {@link #setEventFactory(Class)}), this
   * method returns this class, otherwise it returns {@code null}.
   *
   * @return the event factory, or null if the default should be used
   */
  @Nullable
  public Class<? extends AuditEventFactory> getEventFactory() {
    return this.eventFactory;
  }

  /**
   * By default the {@link DefaultAuditEventFactory} is used to create audit events. By assigning another class that may
   * be overridden.
   * <p>
   * Note that the class given must have a default constructor (i.e., a no-arg constructor).
   * </p>
   *
   * @param eventFactory the event factory to use (null to use default)
   */
  public void setEventFactory(@Nullable final Class<? extends AuditEventFactory> eventFactory) {
    this.eventFactory = eventFactory;
  }

  /**
   * Gets the default principal to assign to audit events. It should be equal to the clientID that the audit logger is
   * servicing. If the audit logger is a system logger, the {@link AuditEvent#DEFAULT_PRINCIPAL} should be used.
   *
   * @return the principal name or null
   */
  @Nullable
  public String getPrincipal() {
    return this.principal;
  }

  /**
   * Assigns the default principal to assign to audit events. It should be equal to the clientID that the audit logger
   * is servicing. If the audit logger is a system logger, the {@link AuditEvent#DEFAULT_PRINCIPAL} should be used.
   *
   * @param principal the principal name
   */
  public void setPrincipal(@Nonnull final String principal) {
    this.principal = Optional.ofNullable(principal)
        .filter(StringUtils::isNotBlank)
        .orElseThrow(() -> new NullPointerException("principal must not be null or empty"));
  }

}
