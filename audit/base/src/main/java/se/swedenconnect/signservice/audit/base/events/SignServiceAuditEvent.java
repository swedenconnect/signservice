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
package se.swedenconnect.signservice.audit.base.events;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditEventParameter;

/**
 * The {@link AuditEvent} implementation SignService Audit Events.
 */
public class SignServiceAuditEvent implements AuditEvent {

  /** For serialization. */
  private static final long serialVersionUID = -5389675099235412855L;

  /** The AuditEvent id. */
  private final String id;

  /** The AuditEvent creation time. */
  private final Instant timestamp;

  /** The AuditEvent principal. */
  private String principal;

  /** The AuditEvent parameters. */
  private final List<AuditEventParameter> parameters;

  /**
   * Instantiates a new audit event.
   *
   * @param id the id
   */
  public SignServiceAuditEvent(@Nonnull final String id) {
    this.id = Objects.requireNonNull(id, "id must not be null");
    this.timestamp = Instant.now();
    this.parameters = new ArrayList<>();
  }

  /**
   * Instantiates a new audit event.
   *
   * @param id the id
   * @param principal the principal
   */
  public SignServiceAuditEvent(@Nonnull final String id, @Nonnull final String principal) {
    this(id);
    this.principal = Objects.requireNonNull(principal, "principal must not be null");
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getId() {
    return this.id;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public Instant getTimestamp() {
    return this.timestamp;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getPrincipal() {
    return this.principal != null ? this.principal : AuditEvent.DEFAULT_PRINCIPAL;
  }

  /** {@inheritDoc} */
  @Override
  public void setPrincipal(@Nonnull final String principal) {
    if (this.principal != null) {
      throw new IllegalArgumentException("principal has already been assigned");
    }
    this.principal = principal;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public List<AuditEventParameter> getParameters() {
    return Collections.unmodifiableList(this.parameters);
  }

  /** {@inheritDoc} */
  @Override
  public void addParameter(@Nonnull final AuditEventParameter parameter) {
    Objects.requireNonNull(parameter, "parameter must not be null");
    int pos = 0;
    for (pos = 0; pos < this.parameters.size(); pos++) {
      if (Objects.equals(this.parameters.get(pos).getName(), parameter.getName())) {
        break;
      }
    }
    if (pos < this.parameters.size()) {
      this.parameters.set(pos, parameter);
    }
    else {
      this.parameters.add(parameter);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void addParameter(@Nonnull final String name, @Nullable final String value) {
    Objects.requireNonNull(name, "name must not be null");
    this.addParameter(new AuditEventParameter(name, value));
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("%s | %s | %s %s",
        this.timestamp, this.getPrincipal(), this.id, this.parameters);
  }

}
