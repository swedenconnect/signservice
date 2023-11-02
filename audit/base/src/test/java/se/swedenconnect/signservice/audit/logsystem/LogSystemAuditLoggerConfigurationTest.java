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
package se.swedenconnect.signservice.audit.logsystem;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for LogSystemAuditLoggerConfiguration.
 */
public class LogSystemAuditLoggerConfigurationTest {

  @Test
  public void testConfig() {
    final LogSystemAuditLoggerConfiguration config = new LogSystemAuditLoggerConfiguration();
    config.setLoggerName("name");

    Assertions.assertEquals(LogSystemAuditLoggerFactory.class.getName(), config.getFactoryClass());
    Assertions.assertEquals("name", config.getLoggerName());
  }

  @Test
  public void testNullAndBlank() {
    final LogSystemAuditLoggerConfiguration config = new LogSystemAuditLoggerConfiguration();

    assertThatThrownBy(() -> {
      config.setLoggerName(null);
    }).isInstanceOf(NullPointerException.class)
        .hasMessage("loggerName must not be null or empty");

    assertThatThrownBy(() -> {
      config.setLoggerName(" ");
    }).isInstanceOf(NullPointerException.class)
        .hasMessage("loggerName must not be null or empty");
  }

}
