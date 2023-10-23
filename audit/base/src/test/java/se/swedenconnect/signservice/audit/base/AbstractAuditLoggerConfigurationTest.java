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

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import javax.annotation.Nonnull;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.audit.base.events.DefaultAuditEventFactory;

/**
 * Test cases for AbstractAuditLoggerConfiguration.
 */
public class AbstractAuditLoggerConfigurationTest {

  @Test
  public void testConfig() {
    final TestAuditLoggerConfiguration config = new TestAuditLoggerConfiguration();
    config.setEventFactory(DefaultAuditEventFactory.class);
    config.setPrincipal("client");

    Assertions.assertEquals(DefaultAuditEventFactory.class, config.getEventFactory());
    Assertions.assertEquals("client", config.getPrincipal());
  }

  @Test
  public void testEmptyPrincipal() {
    final TestAuditLoggerConfiguration config = new TestAuditLoggerConfiguration();

    assertThatThrownBy(() -> {
      config.setPrincipal(null);
    }).isInstanceOf(NullPointerException.class)
        .hasMessage("principal must not be null or empty");
    assertThatThrownBy(() -> {
      config.setPrincipal(" ");
    }).isInstanceOf(NullPointerException.class)
        .hasMessage("principal must not be null or empty");

  }

  // For test
  public static class TestAuditLoggerConfiguration extends AbstractAuditLoggerConfiguration {

    @Override
    @Nonnull
    protected String getDefaultFactoryClass() {
      return "dummy";
    }

  }

}
