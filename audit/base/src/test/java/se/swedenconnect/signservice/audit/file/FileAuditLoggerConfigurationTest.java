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

/**
 * Test cases for FileAuditLoggerConfiguration.
 */
public class FileAuditLoggerConfigurationTest {

  private static final String LOG_FILE = "target/fileaudit.log";

  @Test
  public void testConfig() {
    final FileAuditLoggerConfiguration config = new FileAuditLoggerConfiguration();
    config.setFileName(LOG_FILE);

    Assertions.assertEquals(FileAuditLoggerFactory.class.getName(), config.getFactoryClass());
    Assertions.assertEquals(LOG_FILE, config.getFileName());
  }

  @Test
  public void testNullAndBlank() {
    final FileAuditLoggerConfiguration config = new FileAuditLoggerConfiguration();

    assertThatThrownBy(() -> {
      config.setFileName(null);
    }).isInstanceOf(NullPointerException.class)
        .hasMessage("fileName must not be null or empty");

    assertThatThrownBy(() -> {
      config.setFileName(" ");
    }).isInstanceOf(NullPointerException.class)
        .hasMessage("fileName must not be null or empty");
  }

}
