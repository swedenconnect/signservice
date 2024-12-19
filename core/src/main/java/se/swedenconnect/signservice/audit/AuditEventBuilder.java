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
package se.swedenconnect.signservice.audit;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

/**
 * An interface defining a builder for {@link AuditEvent} objects.
 */
public interface AuditEventBuilder {

  /**
   * Builds the event.
   *
   * @return the audit event
   */
  AuditEvent build();

  /**
   * Assigns the event principal.
   *
   * @param principal the event principal
   * @return the builder
   */
  @Nonnull
  AuditEventBuilder principal(@Nonnull final String principal);

  /**
   * Adds an audit parameter.
   * <p>
   * If an event parameter for this parameter name already exists it will be overwritten.
   * </p>
   *
   * @param parameter the parameter to add
   * @return the builder
   */
  @Nonnull
  AuditEventBuilder parameter(@Nonnull final AuditEventParameter parameter);

  /**
   * Corresponds to {@link #parameter(AuditEventParameter)}.
   *
   * @param name the parameter name (must not be null)
   * @param value the parameter value (may be null)
   * @return the builder
   */
  @Nonnull
  AuditEventBuilder parameter(@Nonnull final String name, @Nullable final String value);
}
