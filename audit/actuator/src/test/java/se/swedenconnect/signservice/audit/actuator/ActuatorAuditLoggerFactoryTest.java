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

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;

import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.core.config.AbstractHandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Test cases for ActuatorAuditLoggerFactory.
 */
public class ActuatorAuditLoggerFactoryTest {

  @Test
  public void testNullConfig() throws Exception {
    final ActuatorAuditLoggerFactory factory = new ActuatorAuditLoggerFactory();

    assertThatThrownBy(() -> {
      factory.create(null);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing configuration for " + ActuatorAuditLogger.class.getSimpleName());
  }

  @Test
  public void testWithConfig() throws Exception {
    final ApplicationEventPublisher mockPublisher = mock(ApplicationEventPublisher.class);

    final ActuatorAuditLoggerConfiguration config = new ActuatorAuditLoggerConfiguration();
    config.setName("AUDIT_LOGGER_HANDLER");
    config.setActive(true);

    final ActuatorAuditLoggerFactory factory = new ActuatorAuditLoggerFactory();
    factory.setPublisher(mockPublisher);
    final AuditLogger logger = factory.create(config);

    Assertions.assertNotNull(logger);
    Assertions.assertTrue(ActuatorAuditLogger.class.isInstance(logger));

    Assertions.assertEquals("AUDIT_LOGGER_HANDLER", logger.getName());

    // Default for active is true
    config.setActive(null);
    Assertions.assertNotNull(factory.create(config));
  }

  @Test
  public void testNotActive() throws Exception {
    final ApplicationEventPublisher mockPublisher = mock(ApplicationEventPublisher.class);

    final ActuatorAuditLoggerConfiguration config = new ActuatorAuditLoggerConfiguration();
    config.setName("AUDIT_LOGGER_HANDLER");
    config.setActive(false);

    final ActuatorAuditLoggerFactory factory = new ActuatorAuditLoggerFactory();
    factory.setPublisher(mockPublisher);


    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("The active property is false - factory should never has been called");
  }

  @Test
  public void testNoPublisher() throws Exception {
    final ActuatorAuditLoggerConfiguration config = new ActuatorAuditLoggerConfiguration();
    config.setName("AUDIT_LOGGER_HANDLER");

    final ActuatorAuditLoggerFactory factory = new ActuatorAuditLoggerFactory();
    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("No ApplicationEventPublisher has been assigned, can not create ");
  }

  @Test
  public void testWithUnknownConfig() {
    final ActuatorAuditLoggerFactory factory = new ActuatorAuditLoggerFactory();
    final HandlerConfiguration<AuditLogger> conf = new AbstractHandlerConfiguration<AuditLogger>() {

      @Override
      protected String getDefaultFactoryClass() {
        return "theclass";
      }
    };
    assertThatThrownBy(() -> {
      factory.create(conf);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Unknown configuration object supplied - ");

  }

}
