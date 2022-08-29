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

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import lombok.Getter;

/**
 * Test cases for AuditLogger
 */
public class AuditLoggerTest {


  @Test
  public void testFunction() {
    final TestAuditLogger logger = new TestAuditLogger();

    logger.auditLog("ID", (b) -> b.build());
    Assertions.assertEquals("ID", logger.getEvents().get(0).getId());

  }

  private static class TestAuditLogger implements AuditLogger {

    @Getter
    private List<AuditEvent> events = new ArrayList<>();

    @Override
    @Nonnull
    public String getName() {
      return "audit";
    }

    @Override
    public void auditLog(@Nonnull final AuditEvent event) throws AuditLoggerException {
      this.events.add(event);
    }

    @Override
    @Nonnull
    public AuditEvent createAuditEvent(@Nonnull final String eventId) {
      final Instant now = Instant.now();

      return new AuditEvent() {
        private static final long serialVersionUID = -4737464584428733444L;

        @Override
        public String getId() {
          return eventId;
        }

        @Override
        public Instant getTimestamp() {
          return now;
        }

        @Override
        public String getPrincipal() {
          return null;
        }

        @Override
        public void setPrincipal(String principal) {
        }

        @Override
        public List<AuditEventParameter> getParameters() {
          return null;
        }

        @Override
        public void addParameter(AuditEventParameter parameter) {
        }

        @Override
        public void addParameter(String name, String value) {
        }

      };
    }

    @Override
    @Nonnull
    public AuditEventBuilder getAuditEventBuilder(@Nonnull final String eventId) {
      final AuditEvent event = this.createAuditEvent(eventId);
      return new AuditEventBuilder() {

        @Override
        public AuditEvent build() {
          return event;
        }

        @Override
        public AuditEventBuilder principal(final String principal) {
          event.setPrincipal(principal);
          return this;
        }

        @Override
        public AuditEventBuilder parameter(final AuditEventParameter parameter) {
          event.addParameter(parameter);
          return null;
        }

        @Override
        public AuditEventBuilder parameter(final String name, final String value) {
          return this.parameter(new AuditEventParameter(name, value));
        }

      };
    }

  }

}
