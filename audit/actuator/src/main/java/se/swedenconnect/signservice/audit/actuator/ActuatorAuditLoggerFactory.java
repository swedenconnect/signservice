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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.springframework.context.ApplicationEventPublisher;

import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.base.AbstractAuditLogger;
import se.swedenconnect.signservice.audit.base.AbstractAuditLoggerFactory;
import se.swedenconnect.signservice.core.config.BeanLoader;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Factory for creating actuator audit logger objects.
 */
public class ActuatorAuditLoggerFactory extends AbstractAuditLoggerFactory {

  /** The ApplicationEventPublisher used to publish events. */
  private ApplicationEventPublisher publisher;

  /** {@inheritDoc} */
  @Override
  @Nonnull
  protected AbstractAuditLogger createAuditLogger(
      @Nonnull final HandlerConfiguration<AuditLogger> configuration, @Nullable final BeanLoader beanLoader)
      throws IllegalArgumentException {

    if (configuration == null) {
      throw new IllegalArgumentException("Missing configuration for " + ActuatorAuditLogger.class.getSimpleName());
    }
    if (!ActuatorAuditLoggerConfiguration.class.isInstance(configuration)) {
      throw new IllegalArgumentException(
          "Unknown configuration object supplied - " + configuration.getClass().getSimpleName());
    }
    final Boolean isActive = ((ActuatorAuditLoggerConfiguration) configuration).getActive();
    if (isActive != null && !isActive.booleanValue()) {
      throw new IllegalArgumentException("The active property is false - factory should never has been called");
    }
    if (this.publisher == null) {
      throw new IllegalArgumentException("No ApplicationEventPublisher has been assigned, can not create "
          + ActuatorAuditLogger.class.getSimpleName());
    }
    return new ActuatorAuditLogger(new ActuatorAuditLoggerListener(this.publisher));
  }

  /**
   * Assigns the ApplicationEventPublisher used to publish events.
   * @param publisher the publisher
   */
  public void setPublisher(@Nonnull final ApplicationEventPublisher publisher) {
    this.publisher = publisher;
  }

}
