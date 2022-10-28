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
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;
import se.swedenconnect.signservice.engine.SignServiceEngine;
import se.swedenconnect.signservice.engine.UnrecoverableErrorCodes;
import se.swedenconnect.signservice.engine.UnrecoverableSignServiceException;

/**
 * Test cases for DefaultSignServiceEngineManager.
 */
public class DefaultSignServiceEngineManagerTest {

  @Test
  public void processGetRequest() throws Exception {

    final HttpRequestMessage msg = Mockito.mock(HttpRequestMessage.class);
    Mockito.when(msg.getUrl()).thenReturn("https://www.example.com/response");
    Mockito.when(msg.getMethod()).thenReturn("GET");

    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    final SignServiceProcessingResult result = Mockito.mock(SignServiceProcessingResult.class);
    Mockito.when(result.getSignServiceContext()).thenReturn(context);
    Mockito.when(result.getHttpRequestMessage()).thenReturn(msg);

    final SignServiceEngine engine = Mockito.mock(SignServiceEngine.class);
    Mockito.when(engine.getName()).thenReturn("ENGINE");
    Mockito.when(engine.canProcess(Mockito.any())).thenReturn(true);
    Mockito.when(engine.processRequest(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(result);

    final TestAuditLogger audit = new TestAuditLogger();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRequestURI()).thenReturn("/sign/process");
    Mockito.when(request.getRemoteAddr()).thenReturn("158.174.14.166");
    Mockito.when(request.getMethod()).thenReturn("GET");

    final HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

    final DefaultSignServiceEngineManager manager = new DefaultSignServiceEngineManager(List.of(engine), audit);

    Assertions.assertTrue(manager.getEngines().size() == 1);
    Assertions.assertNotNull(manager.getSystemAuditLogger());

    // Assert that the ctor audit logs that the system has started.
    Assertions.assertEquals(AuditEventIds.EVENT_SYSTEM_STARTED, audit.events.get(0).getId());
    Assertions.assertTrue(audit.events.get(0).getParameters().isEmpty());

    final SignServiceProcessingResult presult = manager.processRequest(request, response, context);
    Assertions.assertEquals("GET", presult.getHttpRequestMessage().getMethod());
    Assertions.assertEquals("https://www.example.com/response", presult.getHttpRequestMessage().getUrl());
  }

  @Test
  public void processPostRequest() throws Exception {

    final HttpRequestMessage msg = Mockito.mock(HttpRequestMessage.class);
    Mockito.when(msg.getUrl()).thenReturn("https://www.example.com/response");
    Mockito.when(msg.getMethod()).thenReturn("POST");
    Mockito.when(msg.getHttpParameters()).thenReturn(Map.of("p1", "v1", "p2", "v2"));

    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    final SignServiceProcessingResult result = Mockito.mock(SignServiceProcessingResult.class);
    Mockito.when(result.getSignServiceContext()).thenReturn(context);
    Mockito.when(result.getHttpRequestMessage()).thenReturn(msg);

    final SignServiceEngine engine = Mockito.mock(SignServiceEngine.class);
    Mockito.when(engine.getName()).thenReturn("ENGINE");
    Mockito.when(engine.canProcess(Mockito.any())).thenReturn(true);
    Mockito.when(engine.processRequest(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(result);

    final AuditLogger audit = Mockito.mock(AuditLogger.class);

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRequestURI()).thenReturn("/sign/process");
    Mockito.when(request.getRemoteAddr()).thenReturn("158.174.14.166");
    Mockito.when(request.getMethod()).thenReturn("POST");

    final HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

    final DefaultSignServiceEngineManager manager = new DefaultSignServiceEngineManager(Arrays.asList(engine), audit);

    final SignServiceProcessingResult presult = manager.processRequest(request, response, context);
    Assertions.assertEquals("POST", presult.getHttpRequestMessage().getMethod());
    Assertions.assertEquals("https://www.example.com/response", result.getHttpRequestMessage().getUrl());
    Assertions.assertEquals(Map.of("p1", "v1", "p2", "v2"), result.getHttpRequestMessage().getHttpParameters());
  }

  @Test
  public void processResource() throws Exception {

    final SignServiceEngine engine = Mockito.mock(SignServiceEngine.class);
    Mockito.when(engine.getName()).thenReturn("ENGINE");
    Mockito.when(engine.canProcess(Mockito.any())).thenReturn(true);
    Mockito.when(engine.processRequest(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(
        new DefaultSignServiceProcessingResult(null, null));

    final TestAuditLogger audit = new TestAuditLogger();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRequestURI()).thenReturn("/sign/resource");
    Mockito.when(request.getRemoteAddr()).thenReturn("158.174.14.166");
    Mockito.when(request.getMethod()).thenReturn("GET");

    final HttpServletResponse response = Mockito.mock(HttpServletResponse.class);

    final DefaultSignServiceEngineManager manager = new DefaultSignServiceEngineManager(Arrays.asList(engine), audit);

    final SignServiceProcessingResult result = manager.processRequest(request, response, null);
    Assertions.assertNull(result.getHttpRequestMessage());
  }

  @Test
  public void processResourceIOException() throws Exception {

    final SignServiceEngine engine = Mockito.mock(SignServiceEngine.class);
    Mockito.when(engine.getName()).thenReturn("ENGINE");
    Mockito.when(engine.canProcess(Mockito.any())).thenReturn(true);
    Mockito.when(engine.processRequest(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(
        new DefaultSignServiceProcessingResult(null, null));

    final TestAuditLogger audit = new TestAuditLogger();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRequestURI()).thenReturn("/sign/resource");
    Mockito.when(request.getRemoteAddr()).thenReturn("158.174.14.166");
    Mockito.when(request.getMethod()).thenReturn("GET");

    final HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
    Mockito.doThrow(new IOException("IO error")).when(response).flushBuffer();

    final DefaultSignServiceEngineManager manager = new DefaultSignServiceEngineManager(Arrays.asList(engine), audit);

    assertThatThrownBy(() -> {
      manager.processRequest(request, response, null);
    }).isInstanceOf(UnrecoverableSignServiceException.class)
        .hasMessageContaining("Failed to write resource")
        .extracting((e) -> ((UnrecoverableSignServiceException) e).getErrorCode())
        .isEqualTo(UnrecoverableErrorCodes.INTERNAL_ERROR);

    Assertions.assertEquals(AuditEventIds.EVENT_SYSTEM_PROCESSING_ERROR, audit.events.get(1).getId());
    Assertions.assertTrue(audit.events.get(1).getParameters().size() == 4);
  }

  @Test
  public void processResourceException() throws Exception {

    final SignServiceEngine engine = Mockito.mock(SignServiceEngine.class);
    Mockito.when(engine.getName()).thenReturn("ENGINE");
    Mockito.when(engine.canProcess(Mockito.any())).thenReturn(true);
    Mockito.when(engine.processRequest(Mockito.any(), Mockito.any(), Mockito.any()))
      .thenThrow(new UnrecoverableSignServiceException("ERROR", "error"));

    final TestAuditLogger audit = new TestAuditLogger();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getRequestURI()).thenReturn("/sign/resource");
    Mockito.when(request.getRemoteAddr()).thenReturn("158.174.14.166");
    Mockito.when(request.getMethod()).thenReturn("GET");

    final HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
    Mockito.doThrow(new IOException("IO error")).when(response).flushBuffer();

    final DefaultSignServiceEngineManager manager = new DefaultSignServiceEngineManager(Arrays.asList(engine), audit);

    assertThatThrownBy(() -> {
      manager.processRequest(request, response, null);
    }).isInstanceOf(UnrecoverableSignServiceException.class)
        .hasMessage("error")
        .extracting((e) -> ((UnrecoverableSignServiceException) e).getErrorCode())
        .isEqualTo("ERROR");

    Assertions.assertEquals(AuditEventIds.EVENT_SYSTEM_PROCESSING_ERROR, audit.events.get(1).getId());
    Assertions.assertTrue(audit.events.get(1).getParameters().size() == 4);
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

    final DefaultSignServiceEngineManager manager = new DefaultSignServiceEngineManager(Arrays.asList(engine), audit);

    assertThatThrownBy(() -> {
      manager.processRequest(request, response, null);
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
