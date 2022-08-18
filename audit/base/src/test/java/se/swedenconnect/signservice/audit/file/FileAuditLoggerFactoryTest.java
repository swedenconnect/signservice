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
package se.swedenconnect.signservice.audit.file;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.core.config.AbstractHandlerConfiguration;
import se.swedenconnect.signservice.core.config.HandlerConfiguration;

/**
 * Test cases for FileAuditLoggerFactory.
 */
public class FileAuditLoggerFactoryTest {

  private static final String LOG_FILE = "target/fileaudit.log";

  @Test
  public void testNullConfig() throws Exception {
    final FileAuditLoggerFactory factory = new FileAuditLoggerFactory();

    assertThatThrownBy(() -> {
      factory.create(null);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Missing configuration for " + FileAuditLogger.class.getSimpleName());
  }

  @Test
  public void testWithConfig() throws Exception {
    final FileAuditLoggerConfiguration config = new FileAuditLoggerConfiguration();
    config.setName("AUDIT_LOGGER_HANDLER");
    config.setFileName(LOG_FILE);

    final FileAuditLoggerFactory factory = new FileAuditLoggerFactory();
    final AuditLogger logger = factory.create(config);

    Assertions.assertNotNull(logger);
    Assertions.assertTrue(FileAuditLogger.class.isInstance(logger));

    Assertions.assertEquals("AUDIT_LOGGER_HANDLER", logger.getName());
  }

  @Test
  public void testIllegalFileName() throws Exception {
    final FileAuditLoggerConfiguration config = new FileAuditLoggerConfiguration();
    config.setName("AUDIT_LOGGER_HANDLER");
    config.setFileName("target");

    final FileAuditLoggerFactory factory = new FileAuditLoggerFactory();
    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  public void testWithConfigNoFile() throws Exception {
    final FileAuditLoggerConfiguration config = new FileAuditLoggerConfiguration();

    final FileAuditLoggerFactory factory = new FileAuditLoggerFactory();

    assertThatThrownBy(() -> {
      factory.create(config);
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessage("The file-name property must not be null");
  }

  @Test
  public void testWithUnknownConfig() {
    final FileAuditLoggerFactory factory = new FileAuditLoggerFactory();
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
