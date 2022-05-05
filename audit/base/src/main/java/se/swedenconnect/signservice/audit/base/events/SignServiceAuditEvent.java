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

import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditEventParameter;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The {@link AuditEvent} implementation SignService Audit Events
 */
public class SignServiceAuditEvent implements AuditEvent {

  private static final long serialVersionUID = -5389675099235412855L;

  /** The AuditEvent id */
  private final Instant timestamp;

  /** The AuditEvent id */
  private final String id;

  /** The AuditEvent principal */
  private final String principal;

  /** The AuditEvent parameters */
  private final Map<String, AuditEventParameter> parameterMap;

  /**
   * Instantiates a new Sign service audit event.
   *
   * @param id        the id, must not be null
   * @param principal the principal
   */
  public SignServiceAuditEvent(String id, String principal) {
    java.util.Objects.requireNonNull(id, "id must not be null");
    java.util.Objects.requireNonNull(principal, "principal must not be null");
    this.timestamp = Instant.now();
    this.id = id;
    this.principal = principal;
    this.parameterMap = new HashMap<>();
  }

  /** {@inheritDoc} */
  @Override
  public String getId() {
    return id;
  }

  /** {@inheritDoc} */
  @Override
  public String getPrincipal() {
    return principal;
  }

  /** {@inheritDoc} */
  @Override
  public List<AuditEventParameter> getParameters() {
    return new ArrayList<>(parameterMap.values());
  }

  /** {@inheritDoc} */
  @Override
  public void addParameter(AuditEventParameter parameter) {
    Objects.requireNonNull(parameter, "parameter must not be null");
    parameterMap.put(parameter.getName(), parameter);
  }

  /** {@inheritDoc} */
  @Override
  public void addParameter(String name, String value) {
    Objects.requireNonNull(name, "name must not be null");
    parameterMap.put(name, new AuditEventParameter(name, value));
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder("Audit event [")
            .append("timestamp=").append(this.timestamp)
            .append(" principal=").append(this.principal)
            .append(" id=").append(this.id)
            .append(" data=").append(this.parameterMap.values());
    return sb.toString();
  }

}
