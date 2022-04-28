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
package se.signservice.audit.base.events;

import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditEventParameter;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * The {@link AuditEvent} implementation SignService Audit Events
 */
public class SignServiceAuditEvent implements AuditEvent {

  /** The AuditEvent paramaters */
  private final List<AuditEventParameter> parameters;

  /** The AuditEvent id */
  private final String id;

  /**
   * Constructor for SignServiceAuditEvent
   *
   * @param id must not be null
   */
  public SignServiceAuditEvent(String id) {
    Objects.requireNonNull(id, "id must not be null");
    this.id = id;
    this.parameters = new ArrayList<>();
  }

  /** {@inheritDoc} */
  @Override
  public String getId() {
    return id;
  }

  /** {@inheritDoc} */
  @Override
  public List<AuditEventParameter> getParameters() {
    return parameters;
  }

  /** {@inheritDoc} */
  @Override
  public void addParameter(AuditEventParameter parameter) {
    Objects.requireNonNull(parameter, "parameter must not be null");
    parameters.add(parameter);
  }

  /** {@inheritDoc} */
  @Override
  public void addParameter(String name, String value) {
    Objects.requireNonNull(name, "name must not be null");
    parameters.add(new AuditEventParameter(name, value));
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final String paramsStr = parameters.stream()
      .map(AuditEventParameter::toString)
      .collect(Collectors.joining("\n"));
    return String.format("%s\n%s", this.id, paramsStr);
  }
}
