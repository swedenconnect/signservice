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

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * An audit logger event comprises of an event identifier, and optionally followed by a list of name-value pairs.
 */
public interface AuditEvent extends Serializable {

  /** The default principal name that is used when no principal has been assigned to the event. */
  String DEFAULT_PRINCIPAL = "SignService";

  /**
   * Gets the event ID.
   *
   * @return the event ID
   */
  @Nonnull
  String getId();

  /**
   * Gets the timestamp of the event.
   *
   * @return the timestamp
   */
  @Nonnull
  Instant getTimestamp();

  /**
   * Gets the event principal. If no principal has been set, the {@link #DEFAULT_PRINCIPAL} is used.
   *
   * @return the event principal
   */
  @Nonnull
  String getPrincipal();

  /**
   * Assigns the event principal.
   *
   * @param principal the event principal
   */
  void setPrincipal(@Nonnull final String principal);

  /**
   * Gets a list of all audit parameters for this event.
   *
   * @return a (potentially empty) list of audit parameters
   */
  @Nonnull
  List<AuditEventParameter> getParameters();

  /**
   * Adds an audit parameter to the event.
   * <p>
   * If an event parameter for this parameter name already exists it will be overwritten.
   * </p>
   *
   * @param parameter the parameter to add
   */
  void addParameter(@Nonnull final AuditEventParameter parameter);

  /**
   * Corresponds to {@code addParameter(new AuditEventParameter(name, value))}.
   *
   * @param name the parameter name (must not be null)
   * @param value the parameter value (may be null)
   */
  void addParameter(@Nonnull final String name, @Nullable final String value);

  /**
   * The {@code toString} method <b>must</b> be implemented by class implementing the {@link AuditEvent} interface.
   *
   * @return the string representation of the audit event
   */
  @Override
  @Nonnull
  String toString();

}
