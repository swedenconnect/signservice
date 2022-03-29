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
package se.swedenconnect.signservice.protocol.dss;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.w3c.dom.Document;

import se.idsec.signservice.security.certificate.CertificateUtils;
import se.idsec.signservice.xml.DOMUtils;
import se.swedenconnect.signservice.api.protocol.ProtocolException;
import se.swedenconnect.signservice.api.protocol.SignRequestMessage;
import se.swedenconnect.signservice.api.session.SignServiceContext;

/**
 * Test cases for DssProtocolHandler
 */
public class DssProtocolHandlerTest {

  @Test
  public void testDecodeRequest() throws Exception {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    // Setup SignRequest
    final String encodedRequest = DOMUtils.nodeToBase64(
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml")));

    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter("Binding")).thenReturn(DssProtocolHandler.EXPECTED_BINDING);
    Mockito.when(request.getParameter("RelayState")).thenReturn("relay-state");
    Mockito.when(request.getParameter("EidSignRequest")).thenReturn(encodedRequest);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    final SignRequestMessage signRequestMessage = protocolHandler.decodeRequest(request, context);

    Assertions.assertTrue(signRequestMessage instanceof DssSignRequestMessage);
    Assertions.assertEquals("relay-state", signRequestMessage.getRelayState());
    Assertions.assertTrue(signRequestMessage.isSigned());

    // Verify signature ...
    final X509Certificate cert = CertificateUtils.decodeCertificate(this.getClass().getResourceAsStream("/cert1.crt"));

    signRequestMessage.verifySignature(Arrays.asList(cert));
  }

  @Test
  public void testDecodeRequestGET() throws Exception {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    // Setup SignRequest
    final String encodedRequest = DOMUtils.nodeToBase64(
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml")));

    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getParameter("Binding")).thenReturn(DssProtocolHandler.EXPECTED_BINDING);
    Mockito.when(request.getParameter("RelayState")).thenReturn("relay-state");
    Mockito.when(request.getParameter("EidSignRequest")).thenReturn(encodedRequest);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    Assertions.assertThrows(ProtocolException.class, () -> {
      protocolHandler.decodeRequest(request, context);
    });
  }

  @Test
  public void testDecodeRequestBinding() throws Exception {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    // Setup SignRequest
    final String encodedRequest = DOMUtils.nodeToBase64(
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml")));

    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter("Binding")).thenReturn(null);
    Mockito.when(request.getParameter("RelayState")).thenReturn("relay-state");
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
  public void testDecodeRequestRelayStateOptional() throws Exception {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    // Setup SignRequest
    final String encodedRequest = DOMUtils.nodeToBase64(
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml")));

    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter("Binding")).thenReturn(DssProtocolHandler.EXPECTED_BINDING);
    Mockito.when(request.getParameter("RelayState")).thenReturn(null);
    Mockito.when(request.getParameter("EidSignRequest")).thenReturn(encodedRequest);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    final SignRequestMessage signRequestMessage = protocolHandler.decodeRequest(request, context);

    Assertions.assertNull(signRequestMessage.getRelayState());
  }

  @Test
  public void testDecodeRequestMissingSignRequest() throws Exception {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter("Binding")).thenReturn(DssProtocolHandler.EXPECTED_BINDING);
    Mockito.when(request.getParameter("RelayState")).thenReturn("relay-state");
    Mockito.when(request.getParameter("EidSignRequest")).thenReturn(null);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    Assertions.assertThrows(ProtocolException.class, () -> {
      protocolHandler.decodeRequest(request, context);
    });
  }

  @Test
  public void testDecodeRequestMissingInvalidSignRequest() throws Exception {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    final String xml = "<bad-xml>Hello</bad-xml>";

    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter("Binding")).thenReturn(DssProtocolHandler.EXPECTED_BINDING);
    Mockito.when(request.getParameter("RelayState")).thenReturn("relay-state");
    Mockito.when(request.getParameter("EidSignRequest")).thenReturn(Base64.getEncoder().encodeToString(xml.getBytes()));

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    Assertions.assertThrows(ProtocolException.class, () -> {
      protocolHandler.decodeRequest(request, context);
    });
  }

  @Test
  public void testDecodeRequestMissingSignRequestNotBase64() throws Exception {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter("Binding")).thenReturn(DssProtocolHandler.EXPECTED_BINDING);
    Mockito.when(request.getParameter("RelayState")).thenReturn("relay-state");
    Mockito.when(request.getParameter("EidSignRequest")).thenReturn("NOT-BASE64-encoding");

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    Assertions.assertThrows(ProtocolException.class, () -> {
      protocolHandler.decodeRequest(request, context);
    });
  }

  @Test
  public void testDecodeRequestNotAccordingToSpec() throws Exception {
    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    final SignServiceContext context = Mockito.mock(SignServiceContext.class);

    // Setup SignRequest
    final Document doc = DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/request.xml"));
    doc.getDocumentElement().removeAttribute("RequestID");

    final String encodedRequest = DOMUtils.nodeToBase64(doc);

    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter("Binding")).thenReturn(DssProtocolHandler.EXPECTED_BINDING);
    Mockito.when(request.getParameter("RelayState")).thenReturn("relay-state");
    Mockito.when(request.getParameter("EidSignRequest")).thenReturn(encodedRequest);

    final DssProtocolHandler protocolHandler = new DssProtocolHandler();

    Assertions.assertThrows(ProtocolException.class, () -> {
      protocolHandler.decodeRequest(request, context);
    });
  }

}
