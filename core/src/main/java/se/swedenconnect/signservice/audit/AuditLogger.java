/*
 * Copyright 2022-2023 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package se.swedenconnect.signservice.audit;

import java.util.function.Function;

import jakarta.annotation.Nonnull;
import se.swedenconnect.signservice.core.SignServiceHandler;

/**
 * Interface for the Audit Logger used within the SignService system.
 *
 * @see AuditLoggerSingleton
 */
public interface AuditLogger extends SignServiceHandler {

  /**
   * Audit logs the supplied event.
   *
   * @param event the event to be logged
   * @throws AuditLoggerException runtime exception that is thrown if logging fails
   */
  void auditLog(@Nonnull final AuditEvent event) throws AuditLoggerException;

  /**
   * Helper method to audit log in one line.
   *
   * @param eventId the event ID for the event
   * @param build a function that accepts a {@link AuditEventBuilder} and produces the {@link AuditEvent}.
   * @throws AuditLoggerException runtime exception that is thrown if logging fails
   */
  default void auditLog(@Nonnull final String eventId, @Nonnull final Function<AuditEventBuilder, AuditEvent> build)
      throws AuditLoggerException {
    this.auditLog(build.apply(this.getAuditEventBuilder(eventId)));
  }

  /**
   * Creates an event that may be assigned parameters.
   *
   * @param eventId the event ID for the event
   * @return an AuditEvent object
   * @see #getAuditEventBuilder(String)
   */
  @Nonnull
  AuditEvent createAuditEvent(@Nonnull final String eventId);

  /**
   * Gets a builder for building an {@link AuditEvent}.
   *
   * @param eventId the event ID for the event that is being built
   * @return an AuditEventBuilder
   * @see #createAuditEvent(String)
   */
  @Nonnull
  AuditEventBuilder getAuditEventBuilder(@Nonnull final String eventId);

}
