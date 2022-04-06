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
package se.swedenconnect.signservice.audit;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for AuditLoggerSingleton.
 */
public class AuditLoggerSingletonTest {

  @Test
  public void testEmpty() {
    // Should be null since no init has been done
    Assertions.assertNull(AuditLoggerSingleton.getAuditLogger());
  }

  @Test
  public void testInit() {
    try {
      AuditLoggerSingleton.init(new MockedAuditLogger());
      Assertions.assertNotNull(AuditLoggerSingleton.getAuditLogger());
    }
    finally {
      AuditLoggerSingleton.clear();
    }
  }

  @Test
  public void testClear() {
    AuditLoggerSingleton.init(new MockedAuditLogger());
    Assertions.assertNotNull(AuditLoggerSingleton.getAuditLogger());
    AuditLoggerSingleton.clear();
    Assertions.assertNull(AuditLoggerSingleton.getAuditLogger());
  }

  public static class MockedAuditLogger implements AuditLogger {

    @Override
    public void auditLog(final AuditEvent event) throws AuditLoggerException {
    }

    @Override
    public AuditEvent createAuditEvent(final String eventId) {
      return null;
    }

  }
}
