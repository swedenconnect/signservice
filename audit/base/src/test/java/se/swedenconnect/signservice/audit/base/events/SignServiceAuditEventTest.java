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
package se.swedenconnect.signservice.audit.base.events;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditEventParameter;

/**
 * Test cases for SignServiceAuditEvent.
 */
public class SignServiceAuditEventTest {

  @Test
  public void testCreateEvent() {
    SignServiceAuditEvent event = new SignServiceAuditEvent("id", "principal");
    assertThat(event.getId()).isEqualTo("id");
    assertThat(event.getPrincipal()).isEqualTo("principal");

    event = new SignServiceAuditEvent("id");
    assertThat(event.getId()).isEqualTo("id");
    assertThat(event.getPrincipal()).isEqualTo(AuditEvent.DEFAULT_PRINCIPAL);
  }

  @Test
  public void testSetPrincipal() {
    SignServiceAuditEvent event = new SignServiceAuditEvent("id");
    assertThat(event.getPrincipal()).isEqualTo(AuditEvent.DEFAULT_PRINCIPAL);

    event.setPrincipal("PPP");
    assertThat(event.getPrincipal()).isEqualTo("PPP");

    assertThatThrownBy(() -> {
      event.setPrincipal("P2");
    }).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("principal has already been assigned");
  }

  @Test
  public void testAddParameterValues() {
    final SignServiceAuditEvent event = new SignServiceAuditEvent("id", "principal");
    event.addParameter("param1", "value1");
    assertThat(event.getParameters())
        .hasSize(1)
        .extracting(AuditEventParameter::getName)
        .containsExactly("param1");
  }

  @Test
  public void testAddParameterValuesNullValue() {
    final SignServiceAuditEvent event = new SignServiceAuditEvent("id", "principal");
    assertThatThrownBy(() -> {
      event.addParameter(null, "value1");
    }).isInstanceOf(NullPointerException.class)
        .hasMessageContaining("name must not be null");
  }

  @Test
  public void testAddParameter() {
    final SignServiceAuditEvent event = new SignServiceAuditEvent("id", "principal");
    event.addParameter(new AuditEventParameter("param1", "value1"));
    assertThat(event.getParameters())
        .hasSize(1)
        .extracting(AuditEventParameter::getName)
        .containsExactly("param1");
  }

  @Test
  public void testAddParameterDuplicate() {
    final SignServiceAuditEvent event = new SignServiceAuditEvent("id", "principal");
    event.addParameter(new AuditEventParameter("param1", "value1"));
    event.addParameter(new AuditEventParameter("param1", "value2"));
    assertThat(event.getParameters())
        .hasSize(1)
        .extracting(AuditEventParameter::getValue)
        .containsExactly("value2");
  }

  @Test
  public void testAddParameterNullParameter() {
    final SignServiceAuditEvent event = new SignServiceAuditEvent("id", "principal");
    assertThatThrownBy(() -> {
      event.addParameter(null);
    }).isInstanceOf(NullPointerException.class)
        .hasMessageContaining("parameter must not be null");
  }

  @Test
  public void testToString() {
    final SignServiceAuditEvent event = new SignServiceAuditEvent("id", "principal");
    event.addParameter(new AuditEventParameter("param1", "value1"));

    final String msg = " | principal | id [param1='value1']";

    assertThat(event.toString()).contains(msg);
  }

}
