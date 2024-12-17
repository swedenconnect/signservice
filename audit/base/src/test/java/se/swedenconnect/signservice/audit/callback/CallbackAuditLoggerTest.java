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
package se.swedenconnect.signservice.audit.callback;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditLoggerException;

/**
 * Test cases for CallbackAuditLogger.
 */
public class CallbackAuditLoggerTest {

  @Test
  public void testLogger() {

    final List<AuditEvent> events = new ArrayList<>();

    final CallbackAuditLogger logger = new CallbackAuditLogger((e) -> events.add(e));

    logger.auditLog(logger.getAuditEventBuilder("id1")
        .principal("principal")
        .parameter("param1", "value1")
        .build());
    logger.auditLog(logger.getAuditEventBuilder("id2")
        .principal("principal")
        .parameter("param2", "value2")
        .build());

    Assertions.assertEquals(2, events.size());
    Assertions.assertEquals("id1", events.get(0).getId());
    Assertions.assertEquals("id2", events.get(1).getId());
  }

  @Test
  public void testNull() {
    final CallbackAuditLogger logger = new CallbackAuditLogger((e) -> {
    });
    assertThatThrownBy(() -> {
      logger.auditLog(null);
    }).isInstanceOf(AuditLoggerException.class)
        .hasMessage("event must not be null");
  }

  @Test
  public void testErrorLogging() {
    final CallbackAuditLogger logger = new CallbackAuditLogger((e) -> {
      throw new SecurityException("error");
    });
    assertThatThrownBy(() -> {
      logger.auditLog(logger.getAuditEventBuilder("id1")
          .principal("principal")
          .parameter("param1", "value1")
          .build());
    }).isInstanceOf(AuditLoggerException.class)
        .hasMessage("Failed to publish audit event - error");
  }

}
