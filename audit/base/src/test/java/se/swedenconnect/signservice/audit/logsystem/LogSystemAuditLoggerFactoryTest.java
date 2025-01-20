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
package se.swedenconnect.signservice.audit.logsystem;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Field;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.core.config.AbstractHandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Test cases for LogSystemAuditLoggerFactory.
 */
public class LogSystemAuditLoggerFactoryTest {

  @Test
  public void testNullConfig() throws Exception {
    final LogSystemAuditLoggerFactory factory = new LogSystemAuditLoggerFactory();

    assertThatThrownBy(() -> {
      factory.create(null);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing configuration for " + LogSystemAuditLogger.class.getSimpleName());
  }

  @Test
  public void testWithConfig() throws Exception {
    final LogSystemAuditLoggerConfiguration config = new LogSystemAuditLoggerConfiguration();
    config.setName("AUDIT_LOGGER_HANDLER");
    config.setLoggerName("name");

    final LogSystemAuditLoggerFactory factory = new LogSystemAuditLoggerFactory();
    final AuditLogger logger = factory.create(config);

    Assertions.assertNotNull(logger);
    Assertions.assertTrue(LogSystemAuditLogger.class.isInstance(logger));

    Assertions.assertEquals("AUDIT_LOGGER_HANDLER", logger.getName());

    // Assert that auditLog is created and that its name has been set
    final Field internalLoggerField = LogSystemAuditLogger.class.getDeclaredField("auditLogger");
    internalLoggerField.setAccessible(true);
    final Logger internalLogger = (Logger) internalLoggerField.get(logger);
    Assertions.assertNotNull(internalLogger);
    Assertions.assertEquals("name", internalLogger.getName());
  }

  @Test
  public void testWithConfigNoLoggerName() throws Exception {
    final LogSystemAuditLoggerConfiguration config = new LogSystemAuditLoggerConfiguration();

    final LogSystemAuditLoggerFactory factory = new LogSystemAuditLoggerFactory();

    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("The logger-name property must not be null");
  }

  @Test
  public void testWithUnknownConfig() {
    final LogSystemAuditLoggerFactory factory = new LogSystemAuditLoggerFactory();
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
