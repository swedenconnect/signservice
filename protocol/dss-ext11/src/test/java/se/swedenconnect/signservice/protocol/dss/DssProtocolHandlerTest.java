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
package se.swedenconnect.signservice.protocol.dss;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.core.io.ClassPathResource;
import org.w3c.dom.Document;

import se.idsec.signservice.security.certificate.CertificateUtils;
import se.idsec.signservice.utils.ProtocolVersion;
import se.idsec.signservice.xml.DOMUtils;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.http.HttpResponseAction;
import se.swedenconnect.signservice.core.http.HttpUserRequest;
import se.swedenconnect.signservice.engine.SignServiceError;
import se.swedenconnect.signservice.engine.SignServiceErrorCode;
import se.swedenconnect.signservice.protocol.ProtocolException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.SignResponseResult;

/**
 * Test cases for DssProtocolHandler
 */
public class DssProtocolHandlerTest {

  private static final String REQUEST_ID = "da655e67-1104-4ae0-994f-740811ece38d";

  @Test
  public void testName() {
    final DssProtocolHandler protocolHandler = new DssProtocolHandler();
    Assertions.assertEquals(DssProtocolHandler.class.getSimpleName(), protocolHandler.getName());

    protocolHandler.setName("dummy");
    Assertions.assertEquals("dummy", protocolHandler.getName());
  }

  @Test
  public void testDecodeRequest() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    // Setup SignRequest
    final String encodedRequest = DOMUtils.nodeToBase64(
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml")));

    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter("Binding")).thenReturn(DssProtocolHandler.BINDING);
    Mockito.when(request.getParameter("RelayState")).thenReturn(REQUEST_ID);
    Mockito.when(request.getParameter("EidSignRequest")).thenReturn(encodedRequest);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    final SignRequestMessage signRequestMessage = protocolHandler.decodeRequest(request, context);

    Assertions.assertTrue(signRequestMessage instanceof DssSignRequestMessage);
    Assertions.assertEquals(REQUEST_ID, signRequestMessage.getRelayState());
    Assertions.assertEquals(REQUEST_ID, signRequestMessage.getRequestId());
    Assertions.assertTrue(signRequestMessage.isSigned());

    // Verify signature ...
    final X509Certificate cert = CertificateUtils.decodeCertificate(this.getClass().getResourceAsStream("/cert1.crt"));

    signRequestMessage.verifySignature(Arrays.asList(cert));
  }

  @Test
  public void testDecodeRequestGET() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    // Setup SignRequest
    final String encodedRequest = DOMUtils.nodeToBase64(
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml")));

    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getParameter("Binding")).thenReturn(DssProtocolHandler.BINDING);
    Mockito.when(request.getParameter("RelayState")).thenReturn(REQUEST_ID);
    Mockito.when(request.getParameter("EidSignRequest")).thenReturn(encodedRequest);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    Assertions.assertThrows(ProtocolException.class, () -> {
      protocolHandler.decodeRequest(request, context);
    });
  }

  @Test
  public void testDecodeRequestBinding() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    // Setup SignRequest
    final String encodedRequest = DOMUtils.nodeToBase64(
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml")));

    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter("Binding")).thenReturn(null);
    Mockito.when(request.getParameter("RelayState")).thenReturn(REQUEST_ID);
    Mockito.when(request.getParameter("EidSignRequest")).thenReturn(encodedRequest);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    // No Binding - Should work
    protocolHandler.decodeRequest(request, context);

    // Unknown binding - should report an error
    Mockito.when(request.getParameter("Binding")).thenReturn("Dummy-binding");
    Assertions.assertThrows(ProtocolException.class, () -> {
      protocolHandler.decodeRequest(request, context);
    });
  }

  @Test
  public void testDecodeRequestRelayStateMissing() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    // Setup SignRequest
    final String encodedRequest = DOMUtils.nodeToBase64(
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml")));

    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter("Binding")).thenReturn(DssProtocolHandler.BINDING);
    Mockito.when(request.getParameter("RelayState")).thenReturn(null);
    Mockito.when(request.getParameter("EidSignRequest")).thenReturn(encodedRequest);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    Assertions.assertThrows(ProtocolException.class, () -> {
      protocolHandler.decodeRequest(request, context);
    });
  }

  @Test
  public void testDecodeRequestRelayStateMismatch() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    // Setup SignRequest
    final String encodedRequest = DOMUtils.nodeToBase64(
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml")));

    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter("Binding")).thenReturn(DssProtocolHandler.BINDING);
    Mockito.when(request.getParameter("RelayState")).thenReturn("not-request-id");
    Mockito.when(request.getParameter("EidSignRequest")).thenReturn(encodedRequest);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    Assertions.assertThrows(ProtocolException.class, () -> {
      protocolHandler.decodeRequest(request, context);
    });
  }

  @Test
  public void testDecodeRequestMissingSignRequest() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter("Binding")).thenReturn(DssProtocolHandler.BINDING);
    Mockito.when(request.getParameter("RelayState")).thenReturn("relay-state");
    Mockito.when(request.getParameter("EidSignRequest")).thenReturn(null);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    Assertions.assertThrows(ProtocolException.class, () -> {
      protocolHandler.decodeRequest(request, context);
    });
  }

  @Test
  public void testDecodeRequestMissingInvalidSignRequest() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    final String xml = "<bad-xml>Hello</bad-xml>";

    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter("Binding")).thenReturn(DssProtocolHandler.BINDING);
    Mockito.when(request.getParameter("RelayState")).thenReturn(REQUEST_ID);
    Mockito.when(request.getParameter("EidSignRequest")).thenReturn(Base64.getEncoder().encodeToString(xml.getBytes()));

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    Assertions.assertThrows(ProtocolException.class, () -> {
      protocolHandler.decodeRequest(request, context);
    });
  }

  @Test
  public void testDecodeRequestMissingSignRequestNotBase64() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter("Binding")).thenReturn(DssProtocolHandler.BINDING);
    Mockito.when(request.getParameter("RelayState")).thenReturn("relay-state");
    Mockito.when(request.getParameter("EidSignRequest")).thenReturn("NOT-BASE64-encoding");

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    Assertions.assertThrows(ProtocolException.class, () -> {
      protocolHandler.decodeRequest(request, context);
    });
  }

  @Test
  public void testDecodeRequestNotAccordingToSpec() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    // Setup SignRequest
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));
    doc.getDocumentElement().removeAttribute("RequestID");

    final String encodedRequest = DOMUtils.nodeToBase64(doc);

    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter("Binding")).thenReturn(DssProtocolHandler.BINDING);
    Mockito.when(request.getParameter("RelayState")).thenReturn(REQUEST_ID);
    Mockito.when(request.getParameter("EidSignRequest")).thenReturn(encodedRequest);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    Assertions.assertThrows(ProtocolException.class, () -> {
      protocolHandler.decodeRequest(request, context);
    });
  }

  @Test
  public void testCreateResponse() throws Exception {
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();
    final DssSignRequestMessage request = this.getTestRequest();

    final DssSignResponseMessage response =
        (DssSignResponseMessage) protocolHandler.createSignResponseMessage(context, request);

    Assertions.assertEquals(request.getRequestId(), response.getInResponseTo());
    Assertions.assertEquals(request.getRelayState(), response.getRelayState());
    Assertions.assertEquals(request.getVersion(), response.getVersion());
    Assertions.assertEquals(request.getSignServiceId(), response.getIssuerId());
    Assertions.assertEquals(request.getResponseUrl(), response.getDestinationUrl());
  }

  @Test
  public void testCreateResponseMissingSignRequestField() throws Exception {
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    final DssSignRequestMessage request = Mockito.mock(DssSignRequestMessage.class);
    Mockito.when(request.getVersion()).thenReturn(ProtocolVersion.valueOf("1.4"));
    Mockito.when(request.getRequestId()).thenReturn("123456");
    Mockito.when(request.getSignServiceId()).thenReturn(null);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    Assertions.assertThrows(ProtocolException.class, () -> {
      protocolHandler.createSignResponseMessage(context, request);
    });
  }

  @Test
  public void testCreateResponseUnsupportedSignRequest() {
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);
    final SignRequestMessage request = Mockito.mock(SignRequestMessage.class);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      protocolHandler.createSignResponseMessage(context, request);
    });
  }

  @Test
  public void testEncodeResponse() throws Exception {

    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    final DssSignRequestMessage request = this.getTestRequest();
    final DssSignResponseMessage response =
        (DssSignResponseMessage) protocolHandler.createSignResponseMessage(context, request);

    response.setSignResponseResult(new DssSignResponseResult());

    response.sign(this.getTestCredential());

    final HttpResponseAction action = protocolHandler.encodeResponse(response, context);

    Assertions.assertEquals(request.getResponseUrl(), action.getPost().getUrl());
    Assertions.assertNotNull(action.getPost().getParameters().get("EidSignResponse"));
    Assertions.assertEquals(DssProtocolHandler.BINDING, action.getPost().getParameters().get("Binding"));
    Assertions.assertEquals(response.getRelayState(), action.getPost().getParameters().get("RelayState"));
  }

  @Test
  public void testSignNoResult() throws Exception {

    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    final DssSignRequestMessage request = this.getTestRequest();
    final DssSignResponseMessage response =
        (DssSignResponseMessage) protocolHandler.createSignResponseMessage(context, request);

    response.setSignResponseResult(null);

    Assertions.assertThrows(DssProtocolException.class, () -> {
      response.sign(this.getTestCredential());
    });
  }

  @Test
  public void testEncodeResponseNotSigned() throws Exception {

    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();
    final DssSignRequestMessage request = this.getTestRequest();

    final DssSignResponseMessage response =
        (DssSignResponseMessage) protocolHandler.createSignResponseMessage(context, request);

    Assertions.assertThrows(ProtocolException.class, () -> {
      protocolHandler.encodeResponse(response, context);
    });
  }

  @Test
  public void testEncodeMissingDestination() throws Exception {
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();
    final DssSignRequestMessage request = this.getTestRequest();

    final DssSignResponseMessage response =
        (DssSignResponseMessage) protocolHandler.createSignResponseMessage(context, request);
    response.setDestinationUrl(null);

    Assertions.assertThrows(ProtocolException.class, () -> {
      protocolHandler.encodeResponse(response, context);
    });
  }

  @Test
  public void testTranslateError() {
    final DssProtocolHandler protocolHandler = new DssProtocolHandler();
    final SignServiceError error = new SignServiceError(
        SignServiceErrorCode.AUTHN_USER_CANCEL, "User cancel", "User didn't want to continue");

    final SignResponseResult result = protocolHandler.translateError(error);
    Assertions.assertTrue(DssSignResponseResult.class.isInstance(result));
  }

  private DssSignRequestMessage getTestRequest() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    // Setup SignRequest
    final String encodedRequest = DOMUtils.nodeToBase64(
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml")));

    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter("Binding")).thenReturn(DssProtocolHandler.BINDING);
    Mockito.when(request.getParameter("RelayState")).thenReturn(REQUEST_ID);
    Mockito.when(request.getParameter("EidSignRequest")).thenReturn(encodedRequest);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();
    return (DssSignRequestMessage) protocolHandler.decodeRequest(request, context);
  }

  private PkiCredential getTestCredential() throws Exception {
    final KeyStoreCredential cred = new KeyStoreCredential(
        new ClassPathResource("signservice.jks"), "secret".toCharArray(), "signservice", "secret".toCharArray());
    cred.init();
    return cred;
  }

}
