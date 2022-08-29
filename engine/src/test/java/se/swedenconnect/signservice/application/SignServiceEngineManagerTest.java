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
package se.swedenconnect.signservice.application;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import lombok.Getter;
import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditEventIds;
import se.swedenconnect.signservice.audit.AuditEventParameter;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.AuditLoggerException;
import se.swedenconnect.signservice.audit.base.AbstractAuditLogger;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;
import se.swedenconnect.signservice.engine.SignServiceEngine;
import se.swedenconnect.signservice.engine.UnrecoverableErrorCodes;
import se.swedenconnect.signservice.engine.UnrecoverableSignServiceException;

/**
 * Test cases for SignServiceEngineManager.
 */
public class SignServiceEngineManagerTest {

  @Test
  public void processGetRequest() throws Exception {

    final HttpRequestMessage msg = Mockito.mock(HttpRequestMessage.class);
    Mockito.when(msg.getUrl()).thenReturn("https://www.example.com/response");
    Mockito.when(msg.getMethod()).thenReturn("GET");

    final SignServiceEngine engine = Mockito.mock(SignServiceEngine.class);
    Mockito.when(engine.getName()).thenReturn("ENGINE");
    Mockito.when(engine.canProcess(Mockito.any())).thenReturn(true);
    Mockito.when(engine.processRequest(Mockito.any(), Mockito.any())).thenReturn(msg);

    final TestAuditLogger audit = new TestAuditLogger();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRequestURI()).thenReturn("/sign/process");
    Mockito.when(request.getRemoteAddr()).thenReturn("158.174.14.166");
    Mockito.when(request.getMethod()).thenReturn("GET");

    final HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

    final SignServiceEngineManager manager = new SignServiceEngineManager(Arrays.asList(engine), audit);

    // Assert that the ctor audit logs that the system has started.
    Assertions.assertEquals(AuditEventIds.EVENT_SYSTEM_STARTED, audit.events.get(0).getId());
    Assertions.assertTrue(audit.events.get(0).getParameters().isEmpty());

    final HttpRequestMessage result = manager.processRequest(request, response);
    Assertions.assertEquals("GET", result.getMethod());
    Assertions.assertEquals("https://www.example.com/response", result.getUrl());
  }

  @Test
  public void processPostRequest() throws Exception {

    final HttpRequestMessage msg = Mockito.mock(HttpRequestMessage.class);
    Mockito.when(msg.getUrl()).thenReturn("https://www.example.com/response");
    Mockito.when(msg.getMethod()).thenReturn("POST");
    Mockito.when(msg.getHttpParameters()).thenReturn(Map.of("p1", "v1", "p2", "v2"));

    final SignServiceEngine engine = Mockito.mock(SignServiceEngine.class);
    Mockito.when(engine.getName()).thenReturn("ENGINE");
    Mockito.when(engine.canProcess(Mockito.any())).thenReturn(true);
    Mockito.when(engine.processRequest(Mockito.any(), Mockito.any())).thenReturn(msg);

    final AuditLogger audit = Mockito.mock(AuditLogger.class);

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRequestURI()).thenReturn("/sign/process");
    Mockito.when(request.getRemoteAddr()).thenReturn("158.174.14.166");
    Mockito.when(request.getMethod()).thenReturn("POST");

    final HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

    final SignServiceEngineManager manager = new SignServiceEngineManager(Arrays.asList(engine), audit);

    final HttpRequestMessage result = manager.processRequest(request, response);
    Assertions.assertEquals("POST", result.getMethod());
    Assertions.assertEquals("https://www.example.com/response", result.getUrl());
    Assertions.assertEquals(Map.of("p1", "v1", "p2", "v2"), result.getHttpParameters());
  }

  @Test
  public void processResource() throws Exception {

    final SignServiceEngine engine = Mockito.mock(SignServiceEngine.class);
    Mockito.when(engine.getName()).thenReturn("ENGINE");
    Mockito.when(engine.canProcess(Mockito.any())).thenReturn(true);
    Mockito.when(engine.processRequest(Mockito.any(), Mockito.any())).thenReturn(null);

    final TestAuditLogger audit = new TestAuditLogger();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRequestURI()).thenReturn("/sign/resource");
    Mockito.when(request.getRemoteAddr()).thenReturn("158.174.14.166");
    Mockito.when(request.getMethod()).thenReturn("GET");

    final HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

    final SignServiceEngineManager manager = new SignServiceEngineManager(Arrays.asList(engine), audit);

    Assertions.assertNull(manager.processRequest(request, response));
  }

  @Test
  public void processResourceIOException() throws Exception {

    final SignServiceEngine engine = Mockito.mock(SignServiceEngine.class);
    Mockito.when(engine.getName()).thenReturn("ENGINE");
    Mockito.when(engine.canProcess(Mockito.any())).thenReturn(true);
    Mockito.when(engine.processRequest(Mockito.any(), Mockito.any())).thenReturn(null);

    final TestAuditLogger audit = new TestAuditLogger();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRequestURI()).thenReturn("/sign/resource");
    Mockito.when(request.getRemoteAddr()).thenReturn("158.174.14.166");
    Mockito.when(request.getMethod()).thenReturn("GET");

    final HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
    Mockito.doThrow(new IOException("IO error")).when(response).flushBuffer();

    final SignServiceEngineManager manager = new SignServiceEngineManager(Arrays.asList(engine), audit);

    assertThatThrownBy(() -> {
      manager.processRequest(request, response);
    }).isInstanceOf(UnrecoverableSignServiceException.class)
        .hasMessageContaining("Failed to write resource")
        .extracting((e) -> ((UnrecoverableSignServiceException) e).getErrorCode())
        .isEqualTo(UnrecoverableErrorCodes.INTERNAL_ERROR);

    Assertions.assertEquals(AuditEventIds.EVENT_SYSTEM_PROCESSING_ERROR, audit.events.get(1).getId());
    Assertions.assertTrue(audit.events.get(1).getParameters().size() == 3);
  }

  @Test
  public void processResourceException() throws Exception {

    final SignServiceEngine engine = Mockito.mock(SignServiceEngine.class);
    Mockito.when(engine.getName()).thenReturn("ENGINE");
    Mockito.when(engine.canProcess(Mockito.any())).thenReturn(true);
    Mockito.when(engine.processRequest(Mockito.any(), Mockito.any())).thenThrow(new UnrecoverableSignServiceException("ERROR", "error"));

    final TestAuditLogger audit = new TestAuditLogger();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRequestURI()).thenReturn("/sign/resource");
    Mockito.when(request.getRemoteAddr()).thenReturn("158.174.14.166");
    Mockito.when(request.getMethod()).thenReturn("GET");

    final HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
    Mockito.doThrow(new IOException("IO error")).when(response).flushBuffer();

    final SignServiceEngineManager manager = new SignServiceEngineManager(Arrays.asList(engine), audit);

    assertThatThrownBy(() -> {
      manager.processRequest(request, response);
    }).isInstanceOf(UnrecoverableSignServiceException.class)
        .hasMessage("error")
        .extracting((e) -> ((UnrecoverableSignServiceException) e).getErrorCode())
        .isEqualTo("ERROR");

    Assertions.assertEquals(AuditEventIds.EVENT_SYSTEM_PROCESSING_ERROR, audit.events.get(1).getId());
    Assertions.assertTrue(audit.events.get(1).getParameters().size() == 3);
  }

  @Test
  public void processNoMatchingEngine() throws Exception {

    final SignServiceEngine engine = Mockito.mock(SignServiceEngine.class);
    Mockito.when(engine.getName()).thenReturn("ENGINE");
    Mockito.when(engine.canProcess(Mockito.any())).thenReturn(false);

    final TestAuditLogger audit = new TestAuditLogger();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRequestURI()).thenReturn("/sign/process");
    Mockito.when(request.getRemoteAddr()).thenReturn("158.174.14.166");
    Mockito.when(request.getMethod()).thenReturn("GET");

    final HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

    final SignServiceEngineManager manager = new SignServiceEngineManager(Arrays.asList(engine), audit);

    assertThatThrownBy(() -> {
      manager.processRequest(request, response);
    }).isInstanceOf(UnrecoverableSignServiceException.class)
        .hasMessage("No such resource")
        .extracting((e) -> ((UnrecoverableSignServiceException) e).getErrorCode())
        .isEqualTo(UnrecoverableErrorCodes.NOT_FOUND);

    Assertions.assertEquals(AuditEventIds.EVENT_SYSTEM_NOTFOUND, audit.events.get(1).getId());
    Assertions.assertTrue(audit.events.get(1).getParameters().size() == 2);
    Assertions.assertEquals("GET", audit.events.get(1).getParameters().stream()
        .filter(p -> "method".equals(p.getName())).map(AuditEventParameter::getValue).findFirst().orElse(null));
    Assertions.assertEquals("/sign/process", audit.events.get(1).getParameters().stream()
        .filter(p -> "path".equals(p.getName())).map(AuditEventParameter::getValue).findFirst().orElse(null));

  }

  private static class TestAuditLogger extends AbstractAuditLogger {

    @Getter
    private List<AuditEvent> events = new ArrayList<>();

    @Override
    public void auditLog(final AuditEvent event) throws AuditLoggerException {
      events.add(event);
    }

  }

}
