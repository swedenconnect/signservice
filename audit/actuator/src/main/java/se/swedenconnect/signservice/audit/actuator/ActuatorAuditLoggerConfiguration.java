/*
 * Copyright 2022-2024 Sweden Connect
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

import jakarta.annotation.Nonnull;
import se.swedenconnect.signservice.audit.base.AbstractAuditLoggerConfiguration;

/**
 * Configuration for actuator audit logger.
 */
public class ActuatorAuditLoggerConfiguration extends AbstractAuditLoggerConfiguration {

  /**
   * Tells whether to Spring Boot Actuator for audit logging is active. Defaults to {@code true}.
   */
  private Boolean active;

  /**
   * Tells whether to Spring Boot Actuator for audit logging is active. Defaults to {@code true}.
   *
   * @return whether the logger is active
   */
  public Boolean getActive() {
    return this.active;
  }

  /**
   * Tells whether to Spring Boot Actuator for audit logging is active. Defaults to {@code true}.
   *
   * @param active whether the logger is active
   */
  public void setActive(@Nonnull final Boolean active) {
    this.active = active;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected String getDefaultFactoryClass() {
    return ActuatorAuditLoggerFactory.class.getName();
  }

}
