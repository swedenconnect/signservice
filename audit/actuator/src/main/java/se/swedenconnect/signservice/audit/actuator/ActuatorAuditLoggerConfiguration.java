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

import javax.annotation.Nonnull;

import se.swedenconnect.signservice.audit.base.AbstractAuditLoggerConfiguration;

/**
 * Configuration for actuator audit logger.
 */
public class ActuatorAuditLoggerConfiguration extends AbstractAuditLoggerConfiguration {

  /**
   * Tells whether to Spring Boot Actuator for audit logging is active.
   */
  private Boolean active;

  /**
   * Assigns whether to use Spring Boot Actuator for audit logging.
   * @param active flag
   */
  public void setActive(final boolean active) {
    this.active = active;
  }

  /**
   * Gets the {@code active} parameter. If unset it defaults to true.
   * @return the active parameter
   */
  public boolean isActive() {
    return this.active != null ? this.active : true;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected String getDefaultFactoryClass() {
    return ActuatorAuditLoggerFactory.class.getName();
  }

}
