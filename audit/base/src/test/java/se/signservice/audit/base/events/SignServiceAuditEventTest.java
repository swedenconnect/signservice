package se.signservice.audit.base.events;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import se.swedenconnect.signservice.audit.AuditEventParameter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SignServiceAuditEventTest {

  @Test
  void testCreateEvent() {
    SignServiceAuditEvent event = new SignServiceAuditEvent("id", "principal");
    assertThat(event.getId()).isEqualTo("id");
    assertThat(event.getPrincipal()).isEqualTo("principal");
  }

  @Test
  void testAddParameterValues() {
    SignServiceAuditEvent event = new SignServiceAuditEvent("id", "principal");
    event.addParameter("param1", "value1");
    assertThat(event.getParameters())
      .hasSize(1)
      .extracting(AuditEventParameter::getName)
      .containsExactly("param1");
  }

  @Test
  void testAddParameterValues_whenNameNull_throwException() {
    SignServiceAuditEvent event = new SignServiceAuditEvent("id", "principal");
    assertThatThrownBy(() -> {
      event.addParameter(null, "value1");
    }).isInstanceOf(NullPointerException.class)
      .hasMessageContaining("name must not be null");
  }

  @Test
  void testAddParameter() {
    SignServiceAuditEvent event = new SignServiceAuditEvent("id", "principal");
    event.addParameter(new AuditEventParameter("param1", "value1"));
    assertThat(event.getParameters())
      .hasSize(1)
      .extracting(AuditEventParameter::getName)
      .containsExactly("param1");
  }

  @Test
  void testAddParameter_whenDuplicate_overwrite() {
    SignServiceAuditEvent event = new SignServiceAuditEvent("id", "principal");
    event.addParameter(new AuditEventParameter("param1", "value1"));
    event.addParameter(new AuditEventParameter("param1", "value2"));
    assertThat(event.getParameters())
      .hasSize(1)
      .extracting(AuditEventParameter::getValue)
      .containsExactly("value2");
  }

  @Test
  void testAddParameter_whenParamNull_throwException() {
    SignServiceAuditEvent event = new SignServiceAuditEvent("id", "principal");
    assertThatThrownBy(() -> {
      event.addParameter(null);
    }).isInstanceOf(NullPointerException.class)
      .hasMessageContaining("parameter must not be null");
  }

  @Test
  void testToString() {
    SignServiceAuditEvent event = new SignServiceAuditEvent("id", "principal");
    event.addParameter(new AuditEventParameter("param1", "value1"));

    assertThat(event.toString())
      .contains("type=id")
      .contains("principal=principal")
      .contains("data=[param1='value1']");
  }

}