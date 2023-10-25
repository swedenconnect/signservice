/*
 * Copyright 2022-2023 Sweden Connect
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

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
import se.swedenconnect.signservice.core.http.DefaultHttpBodyAction;
import se.swedenconnect.signservice.core.http.DefaultHttpPostAction;
import se.swedenconnect.signservice.core.http.DefaultHttpRedirectAction;
import se.swedenconnect.signservice.core.http.DefaultHttpResponseAction;
import se.swedenconnect.signservice.core.http.HttpResponseAction;
import se.swedenconnect.signservice.core.http.HttpUserRequest;
import se.swedenconnect.signservice.engine.SignServiceEngine;
import se.swedenconnect.signservice.engine.UnrecoverableErrorCodes;
import se.swedenconnect.signservice.engine.UnrecoverableSignServiceException;

/**
 * Test cases for DefaultSignServiceEngineManager.
 */
public class DefaultSignServiceEngineManagerTest {

  @Test
  public void processGetRequest() throws Exception {

    final HttpResponseAction msg = new DefaultHttpResponseAction(
        new DefaultHttpRedirectAction("https://www.example.com/response"));

    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    final SignServiceProcessingResult result = Mockito.mock(SignServiceProcessingResult.class);
    Mockito.when(result.getSignServiceContext()).thenReturn(context);
    Mockito.when(result.getResponseAction()).thenReturn(msg);

    final SignServiceEngine engine = Mockito.mock(SignServiceEngine.class);
    Mockito.when(engine.getName()).thenReturn("ENGINE");
    Mockito.when(engine.canProcess(Mockito.any())).thenReturn(true);
    Mockito.when(engine.processRequest(Mockito.any(), Mockito.any())).thenReturn(result);

    final TestAuditLogger audit = new TestAuditLogger();

    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getRequestUrl()).thenReturn("https://www.example.com/sign/process");
    Mockito.when(request.getClientIpAddress()).thenReturn("158.174.14.166");
    Mockito.when(request.getMethod()).thenReturn("GET");

    final DefaultSignServiceEngineManager manager = new DefaultSignServiceEngineManager(List.of(engine), audit);

    Assertions.assertTrue(manager.getEngines().size() == 1);
    Assertions.assertNotNull(manager.getSystemAuditLogger());

    // Assert that the ctor audit logs that the system has started.
    Assertions.assertEquals(AuditEventIds.EVENT_SYSTEM_STARTED, audit.events.get(0).getId());
    Assertions.assertTrue(audit.events.get(0).getParameters().isEmpty());

    final SignServiceProcessingResult presult = manager.processRequest(request, context);
    Assertions.assertNotNull(presult.getResponseAction().getRedirect());
    Assertions.assertEquals("https://www.example.com/response", presult.getResponseAction().getRedirect().getUrl());
  }

  @Test
  public void processPostRequest() throws Exception {

    final HttpResponseAction msg = new DefaultHttpResponseAction(
        DefaultHttpPostAction.builder()
          .url("https://www.example.com/response")
          .parameter("p1", "v1")
          .parameter("p2", "v2")
          .build());

    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    final SignServiceProcessingResult result = Mockito.mock(SignServiceProcessingResult.class);
    Mockito.when(result.getSignServiceContext()).thenReturn(context);
    Mockito.when(result.getResponseAction()).thenReturn(msg);

    final SignServiceEngine engine = Mockito.mock(SignServiceEngine.class);
    Mockito.when(engine.getName()).thenReturn("ENGINE");
    Mockito.when(engine.canProcess(Mockito.any())).thenReturn(true);
    Mockito.when(engine.processRequest(Mockito.any(), Mockito.any())).thenReturn(result);

    final AuditLogger audit = Mockito.mock(AuditLogger.class);

    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getRequestUrl()).thenReturn("https://www.example.com/sign/process");
    Mockito.when(request.getClientIpAddress()).thenReturn("158.174.14.166");
    Mockito.when(request.getMethod()).thenReturn("POST");

    final DefaultSignServiceEngineManager manager = new DefaultSignServiceEngineManager(Arrays.asList(engine), audit);

    final SignServiceProcessingResult presult = manager.processRequest(request, context);
    Assertions.assertNotNull(presult.getResponseAction().getPost());
    Assertions.assertEquals("https://www.example.com/response", presult.getResponseAction().getPost().getUrl());
    Assertions.assertEquals(Map.of("p1", "v1", "p2", "v2"), presult.getResponseAction().getPost().getParameters());
  }

  @Test
  public void processResource() throws Exception {

    final SignServiceEngine engine = Mockito.mock(SignServiceEngine.class);
    Mockito.when(engine.getName()).thenReturn("ENGINE");
    Mockito.when(engine.canProcess(Mockito.any())).thenReturn(true);
    Mockito.when(engine.processRequest(Mockito.any(), Mockito.any())).thenReturn(
        new DefaultSignServiceProcessingResult(null,
            new DefaultHttpResponseAction(
                DefaultHttpBodyAction.builder()
                  .contents("contents".getBytes())
                  .header("h1", "v1")
                  .build())));

    final TestAuditLogger audit = new TestAuditLogger();

    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getRequestUrl()).thenReturn("https://www.example.com/sign/resource");
    Mockito.when(request.getClientIpAddress()).thenReturn("158.174.14.166");
    Mockito.when(request.getMethod()).thenReturn("GET");
    final DefaultSignServiceEngineManager manager = new DefaultSignServiceEngineManager(Arrays.asList(engine), audit);

    final SignServiceProcessingResult result = manager.processRequest(request, null);
    Assertions.assertNotNull(result.getResponseAction().getBody());
  }

  @Test
  public void processResourceException() throws Exception {

    final SignServiceEngine engine = Mockito.mock(SignServiceEngine.class);
    Mockito.when(engine.getName()).thenReturn("ENGINE");
    Mockito.when(engine.canProcess(Mockito.any())).thenReturn(true);
    Mockito.when(engine.processRequest(Mockito.any(), Mockito.any()))
      .thenThrow(new UnrecoverableSignServiceException("ERROR", "error"));

    final TestAuditLogger audit = new TestAuditLogger();

    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getRequestUrl()).thenReturn("https://www.example.com/sign/resource");
    Mockito.when(request.getClientIpAddress()).thenReturn("158.174.14.166");
    Mockito.when(request.getMethod()).thenReturn("GET");

    final DefaultSignServiceEngineManager manager = new DefaultSignServiceEngineManager(Arrays.asList(engine), audit);

    assertThatThrownBy(() -> {
      manager.processRequest(request, null);
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

    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getRequestUrl()).thenReturn("https://www.example.com/sign/process");
    Mockito.when(request.getClientIpAddress()).thenReturn("158.174.14.166");
    Mockito.when(request.getMethod()).thenReturn("GET");

    final DefaultSignServiceEngineManager manager = new DefaultSignServiceEngineManager(Arrays.asList(engine), audit);

    assertThatThrownBy(() -> {
      manager.processRequest(request, null);
    }).isInstanceOf(UnrecoverableSignServiceException.class)
        .hasMessage("No such resource")
        .extracting((e) -> ((UnrecoverableSignServiceException) e).getErrorCode())
        .isEqualTo(UnrecoverableErrorCodes.NOT_FOUND);

    Assertions.assertEquals(AuditEventIds.EVENT_SYSTEM_NOTFOUND, audit.events.get(1).getId());
    Assertions.assertTrue(audit.events.get(1).getParameters().size() == 2);
    Assertions.assertEquals("GET", audit.events.get(1).getParameters().stream()
        .filter(p -> "method".equals(p.getName())).map(AuditEventParameter::getValue).findFirst().orElse(null));
    Assertions.assertEquals("https://www.example.com/sign/process", audit.events.get(1).getParameters().stream()
        .filter(p -> "url".equals(p.getName())).map(AuditEventParameter::getValue).findFirst().orElse(null));

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
