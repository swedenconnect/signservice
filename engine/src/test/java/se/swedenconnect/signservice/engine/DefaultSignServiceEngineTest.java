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
package se.swedenconnect.signservice.engine;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import lombok.Getter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.application.SignServiceProcessingResult;
import se.swedenconnect.signservice.audit.AuditEvent;
import se.swedenconnect.signservice.audit.AuditEventIds;
import se.swedenconnect.signservice.audit.AuditEventParameter;
import se.swedenconnect.signservice.audit.AuditLoggerException;
import se.swedenconnect.signservice.audit.base.AbstractAuditLogger;
import se.swedenconnect.signservice.authn.AuthenticationErrorCode;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.authn.AuthenticationResult;
import se.swedenconnect.signservice.authn.AuthenticationResultChoice;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.authn.UserAuthenticationException;
import se.swedenconnect.signservice.authn.impl.SimpleAuthnContextIdentifier;
import se.swedenconnect.signservice.certificate.CertificateAttributeType;
import se.swedenconnect.signservice.certificate.CertificateType;
import se.swedenconnect.signservice.certificate.KeyAndCertificateHandler;
import se.swedenconnect.signservice.client.ClientConfiguration;
import se.swedenconnect.signservice.core.attribute.impl.DefaultIdentityAttributeIdentifier;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;
import se.swedenconnect.signservice.core.http.HttpResourceProvider;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.engine.config.EngineConfiguration;
import se.swedenconnect.signservice.protocol.ProtocolException;
import se.swedenconnect.signservice.protocol.ProtocolHandler;
import se.swedenconnect.signservice.protocol.ProtocolProcessingRequirements;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.SignResponseMessage;
import se.swedenconnect.signservice.protocol.SignResponseResult;
import se.swedenconnect.signservice.protocol.msg.SignMessage;
import se.swedenconnect.signservice.protocol.msg.SignerAuthnInfo;
import se.swedenconnect.signservice.protocol.msg.SigningCertificateRequirements;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultCertificateAttributeMapping;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultRequestedCertificateAttribute;
import se.swedenconnect.signservice.signature.CompletedSignatureTask;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;
import se.swedenconnect.signservice.signature.SignatureHandler;
import se.swedenconnect.signservice.storage.MessageReplayChecker;
import se.swedenconnect.signservice.storage.MessageReplayException;

/**
 * Test cases for DefaultSignServiceEngine.
 */
public class DefaultSignServiceEngineTest {

  private static final String SIGNREQUEST_PATH = "/sign";
  private static final String METADATA_PATH = "/metadata";
  private static final String SAML_POST_PATH = "/saml/post";
  private static final String CLIENT_RESPONSE_URL = "https://client.example.com/sign";
  private static final String RESOURCE_PATH = "/resource";
  private static final String ERROR_RESOURCE_PATH = "/resource2";

  private EngineConfiguration engineConfiguration;
  private KeyAndCertificateHandler certHandler;
  private AuthenticationHandler authnHandler;
  private ProtocolHandler protHandler;

  private MessageReplayChecker messageReplayChecker;

  private SignRequestMessageVerifier signRequestMessageVerifier;

  private TestAuditLogger systemAuditLogger;
  private TestAuditLogger auditLogger;

  private SignRequestMessage signRequestMessage;

  private HttpServletRequest httpRequest;

  private HttpServletResponse httpResponse;

  @BeforeEach
  public void setup() throws Exception {
    this.engineConfiguration = mock(EngineConfiguration.class);
    when(this.engineConfiguration.getName()).thenReturn("Engine");
    when(this.engineConfiguration.getProcessingPaths()).thenReturn(List.of(SIGNREQUEST_PATH));

    final HttpResourceProvider provider1 = mock(HttpResourceProvider.class);
    doNothing().when(provider1).getResource(any(), any());
    when(provider1.supports(any())).thenAnswer(a -> {
      final HttpServletRequest req = a.getArgument(0, HttpServletRequest.class);
      return RESOURCE_PATH.equals(req.getServletPath());
    });
    final HttpResourceProvider provider2 = mock(HttpResourceProvider.class);
    doThrow(IOException.class).when(provider2).getResource(any(), any());
    when(provider2.supports(any())).thenAnswer(a -> {
      final HttpServletRequest req = a.getArgument(0, HttpServletRequest.class);
      return ERROR_RESOURCE_PATH.equals(req.getServletPath());
    });
    when(this.engineConfiguration.getHttpResourceProviders()).thenReturn(List.of(provider1, provider2));

    final ClientConfiguration clientConf = mock(ClientConfiguration.class);
    when(clientConf.getClientId()).thenReturn("clientID");
    when(this.engineConfiguration.getClientConfiguration()).thenReturn(clientConf);

    this.auditLogger = new TestAuditLogger();
    when(this.engineConfiguration.getAuditLogger()).thenReturn(this.auditLogger);

    this.authnHandler = mock(AuthenticationHandler.class);
    when(this.authnHandler.getName()).thenReturn("DummyAuthn");

    when(this.authnHandler.canProcess(any(), any())).thenAnswer(a -> {
      final HttpServletRequest req = a.getArgument(0, HttpServletRequest.class);
      return SAML_POST_PATH.equals(req.getServletPath()) || METADATA_PATH.equals(req.getServletPath());
    });

    final HttpRequestMessage authnRequest = mock(HttpRequestMessage.class);
    final AuthenticationResultChoice arc1 = new AuthenticationResultChoice(authnRequest);
    when(this.authnHandler.authenticate(any(), any(), any())).thenReturn(arc1);

    final AuthenticationResult ar = mock(AuthenticationResult.class);
    when(ar.signMessageDisplayed()).thenReturn(true);
    when(ar.getAssertion()).thenAnswer(e -> {
      return this.setupIdentityAssertion();
    });
    final AuthenticationResultChoice arc2 = new AuthenticationResultChoice(ar);
    when(this.authnHandler.resumeAuthentication(any(), any())).thenReturn(arc2);

    when(this.engineConfiguration.getAuthenticationHandler()).thenReturn(this.authnHandler);

    this.signRequestMessage = this.setupSignRequestMessage();
    this.protHandler = mock(ProtocolHandler.class);

    when(protHandler.decodeRequest(any(), any())).thenReturn(this.signRequestMessage);

    when(protHandler.createSignResponseMessage(any(), any())).thenReturn(new MockSignResponseMessage());

    when(protHandler.translateError(any())).thenAnswer(e -> {
      final SignServiceError error = e.getArgument(0, SignServiceError.class);
      return new SignResponseResult() {
        private static final long serialVersionUID = 6720617489120814592L;

        @Override
        public boolean isSuccess() {
          return false;
        }

        @Override
        public String getErrorCode() {
          return error.getErrorCode().name();
        }

        @Override
        public String getMinorErrorCode() {
          return null;
        }

        @Override
        public String getMessage() {
          return error.getMessage();
        }

      };
    });

    when(protHandler.encodeResponse(any(), any())).thenAnswer(e -> {
      final SignResponseMessage srm = e.getArgument(0, SignResponseMessage.class);
      return new HttpRequestMessage() {

        @Override
        public String getUrl() {
          return CLIENT_RESPONSE_URL;
        }

        @Override
        public String getMethod() {
          return "POST";
        }

        @Override
        public Map<String, String> getHttpParameters() {
          final Map<String, String> map = new HashMap<>();
          if (srm != null) {
            map.put("result-code", srm.getSignResponseResult().isSuccess()
                ? "SUCCESS"
                : srm.getSignResponseResult().getErrorCode());
          }
          return map;
        }

        @Override
        public Map<String, String> getHttpHeaders() {
          return null;
        }
      };
    });

    when(this.engineConfiguration.getProtocolHandler()).thenReturn(protHandler);

    this.certHandler = mock(KeyAndCertificateHandler.class);
    doNothing().when(this.certHandler).checkRequirements(any(), any());
    final PkiCredential signingCred = mock(PkiCredential.class);
    when(this.certHandler.generateSigningCredential(any(), any(), any())).thenReturn(signingCred);
    when(this.engineConfiguration.getKeyAndCertificateHandler()).thenReturn(this.certHandler);

    final SignatureHandler sigHandler = mock(SignatureHandler.class);
    doNothing().when(sigHandler).checkRequirements(any(), any());
    final CompletedSignatureTask cst = mock(CompletedSignatureTask.class);
    when(sigHandler.sign(any(), any(), any(), any())).thenReturn(cst);
    when(this.engineConfiguration.getSignatureHandler()).thenReturn(sigHandler);

    this.messageReplayChecker = mock(MessageReplayChecker.class);
    doNothing().when(this.messageReplayChecker).checkReplay(any());

    this.signRequestMessageVerifier = mock(SignRequestMessageVerifier.class);
    doNothing().when(this.signRequestMessageVerifier).verifyMessage(any(), any(), any());

    this.systemAuditLogger = new TestAuditLogger();

    this.httpRequest = mock(HttpServletRequest.class);
    when(this.httpRequest.getServletPath()).thenReturn(SIGNREQUEST_PATH);
    when(this.httpRequest.getRemoteAddr()).thenReturn("187.11.12.45");

    this.httpResponse = mock(HttpServletResponse.class);
  }

  private SignRequestMessage setupSignRequestMessage() {
    final SignRequestMessage msg = mock(SignRequestMessage.class);
    when(msg.getSignServiceId()).thenReturn("signservice");
    when(msg.getClientId()).thenReturn("clientID");
    when(msg.getRequestId()).thenReturn("REQUEST_ID");
    when(msg.getRelayState()).thenReturn("REQUEST_ID");
    when(msg.getResponseUrl()).thenReturn(CLIENT_RESPONSE_URL);
    final SignMessage sm = mock(SignMessage.class);
    when(sm.getMustShow()).thenReturn(true);
    when(msg.getSignMessage()).thenReturn(sm);

    final SigningCertificateRequirements scr = mock(SigningCertificateRequirements.class);
    when(scr.getCertificateType()).thenReturn(CertificateType.PKC);

    final DefaultCertificateAttributeMapping cam1 = new DefaultCertificateAttributeMapping();
    cam1.setSources(List.of(
        new DefaultIdentityAttributeIdentifier("saml", "urn:oid:1.2.752.29.4.13", null)));
    final DefaultRequestedCertificateAttribute drca1 =
        new DefaultRequestedCertificateAttribute(CertificateAttributeType.RDN, "2.5.4.5");
    drca1.setRequired(true);
    cam1.setDestination(drca1);

    final DefaultCertificateAttributeMapping cam2 = new DefaultCertificateAttributeMapping();
    cam2.setSources(List.of(
        new DefaultIdentityAttributeIdentifier("saml", "urn:oid:2.5.4.3", null)));
    cam2.setDestination(new DefaultRequestedCertificateAttribute(CertificateAttributeType.RDN, "2.5.4.3"));

    when(scr.getAttributeMappings()).thenReturn(List.of(cam1, cam2));
    when(msg.getSigningCertificateRequirements()).thenReturn(scr);

    final RequestedSignatureTask task = mock(RequestedSignatureTask.class);
    when(msg.getSignatureTasks()).thenReturn(List.of(task));

    return msg;
  }

  private IdentityAssertion setupIdentityAssertion() {
    final IdentityAssertion ia = mock(IdentityAssertion.class);
    when(ia.getScheme()).thenReturn("saml");
    when(ia.getIdentifier()).thenReturn("assertionID");
    when(ia.getAuthnContext()).thenReturn(new SimpleAuthnContextIdentifier("http://id.elegnamnden.se/loa/1.0/loa3"));
    when(ia.getAuthnInstant()).thenReturn(Instant.now().minusSeconds(20));
    when(ia.getEncodedAssertion()).thenReturn("dummy".getBytes());
    when(ia.getIssuanceInstant()).thenReturn(Instant.now().minusSeconds(19));
    when(ia.getIssuer()).thenReturn("https://idp.example.com");
    when(ia.getIdentityAttributes()).thenReturn(List.of(
        new StringSamlIdentityAttribute("urn:oid:1.2.752.29.4.13", null, "191212121212"),
        new StringSamlIdentityAttribute("urn:oid:2.5.4.3", null, "Kalle Kula")));
    return ia;
  }

  @Test
  public void testInit() {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    assertDoesNotThrow(() -> {
      engine.init();
    });

    // Assert that the system audit logger was invoked ...
    Assertions.assertTrue(this.systemAuditLogger.getEvents().size() == 1);
    Assertions.assertEquals(AuditEventIds.EVENT_ENGINE_STARTED, this.systemAuditLogger.getEvents().get(0).getId());
  }

  @Test
  public void testInitCreateDefaultVerifier() {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);

    assertDoesNotThrow(() -> {
      engine.init();
    });
  }

  @Test
  public void testProcessSignRequest() throws Exception {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    SignServiceProcessingResult result = engine.processRequest(this.httpRequest, this.httpResponse, null);
    Assertions.assertNotNull(result);
    Assertions.assertNotNull(result.getSignServiceContext());

    // OK, now the user has been to the IdP and is posted back ...

    when(this.httpRequest.getServletPath()).thenReturn(SAML_POST_PATH);

    result = engine.processRequest(this.httpRequest, this.httpResponse, result.getSignServiceContext());
    Assertions.assertNotNull(result);
    Assertions.assertNull(result.getSignServiceContext());
    Assertions.assertEquals("SUCCESS", result.getHttpRequestMessage().getHttpParameters().get("result-code"));

    // Assert audit logging
    final TestAuditLogger auditLogger = (TestAuditLogger) this.engineConfiguration.getAuditLogger();
    Assertions.assertTrue(auditLogger.getEvents().size() == 2);
    Assertions.assertEquals(AuditEventIds.EVENT_ENGINE_USER_AUTHENTICATED, auditLogger.getEvents().get(0).getId());
    Assertions.assertEquals(AuditEventIds.EVENT_ENGINE_SIGNATURE_OPERATION_SUCCESS,
        auditLogger.getEvents().get(1).getId());
  }

  @Test
  public void testProcessSignRequestAbandonedSession() throws Exception {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    SignServiceProcessingResult result = engine.processRequest(this.httpRequest, this.httpResponse, null);
    Assertions.assertNotNull(result);
    Assertions.assertNotNull(result.getSignServiceContext());

    // Send a new request. The previous session will be abandoned ...
    result = engine.processRequest(this.httpRequest, this.httpResponse, result.getSignServiceContext());
    Assertions.assertNotNull(result);
    Assertions.assertNotNull(result.getSignServiceContext());

    final TestAuditLogger auditLogger = (TestAuditLogger) this.engineConfiguration.getAuditLogger();
    Assertions.assertTrue(auditLogger.getEvents().size() == 1);
    Assertions.assertEquals(AuditEventIds.EVENT_ENGINE_SESSION_RESET, auditLogger.getEvents().get(0).getId());

    // OK, now the user has been to the IdP and is posted back ...

    when(this.httpRequest.getServletPath()).thenReturn(SAML_POST_PATH);

    result = engine.processRequest(this.httpRequest, this.httpResponse, result.getSignServiceContext());
    Assertions.assertNotNull(result);
    Assertions.assertNull(result.getSignServiceContext());
    Assertions.assertEquals("SUCCESS", result.getHttpRequestMessage().getHttpParameters().get("result-code"));

    // Assert audit logging
    Assertions.assertTrue(auditLogger.getEvents().size() == 3);
    Assertions.assertEquals(AuditEventIds.EVENT_ENGINE_USER_AUTHENTICATED, auditLogger.getEvents().get(1).getId());
    Assertions.assertEquals(AuditEventIds.EVENT_ENGINE_SIGNATURE_OPERATION_SUCCESS,
        auditLogger.getEvents().get(2).getId());
  }

  @Test
  public void testProcessSignRequestReplayCheckerError() throws Exception {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    doThrow(MessageReplayException.class).when(this.messageReplayChecker).checkReplay(any());

    assertThatThrownBy(() -> {
      engine.processRequest(this.httpRequest, this.httpResponse, null);
    }).isInstanceOf(UnrecoverableSignServiceException.class)
        .hasMessage("Message is already being processed")
        .extracting((e) -> UnrecoverableSignServiceException.class.cast(e).getErrorCode())
        .isEqualTo(UnrecoverableErrorCodes.REPLAY_ATTACK);

    // Assert audit logging
    final TestAuditLogger auditLogger = (TestAuditLogger) this.engineConfiguration.getAuditLogger();
    Assertions.assertTrue(auditLogger.getEvents().size() == 1);
    Assertions.assertEquals(AuditEventIds.EVENT_ENGINE_SIGNATURE_OPERATION_FAILURE,
        auditLogger.getEvents().get(0).getId());
    Assertions.assertEquals(UnrecoverableErrorCodes.REPLAY_ATTACK,
        auditLogger.getEvents().get(0).getParameters().stream().filter(p -> "error-code".equals(p.getName()))
            .map(AuditEventParameter::getValue).findFirst().orElse(null));
  }

  @Test
  public void testProcessSignRequestDecodeError() throws Exception {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    when(protHandler.decodeRequest(any(), any())).thenThrow(ProtocolException.class);

    assertThatThrownBy(() -> {
      engine.processRequest(this.httpRequest, this.httpResponse, null);
    }).isInstanceOf(UnrecoverableSignServiceException.class)
        .hasMessage("Failed to decode sign request")
        .extracting((e) -> UnrecoverableSignServiceException.class.cast(e).getErrorCode())
        .isEqualTo(UnrecoverableErrorCodes.PROTOCOL_ERROR);
  }

  @Test
  public void testProcessSignRequestCheckRequirementsFailed() throws Exception {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    doThrow(InvalidRequestException.class).when(this.certHandler).checkRequirements(any(), any());

    final SignServiceProcessingResult result = engine.processRequest(this.httpRequest, this.httpResponse, null);
    Assertions.assertNull(result.getSignServiceContext());
    Assertions.assertEquals(SignServiceErrorCode.REQUEST_INCORRECT.name(),
        result.getHttpRequestMessage().getHttpParameters().get("result-code"));

    // Assert audit logging
    final TestAuditLogger auditLogger = (TestAuditLogger) this.engineConfiguration.getAuditLogger();
    Assertions.assertTrue(auditLogger.getEvents().size() == 1);
    Assertions.assertEquals(AuditEventIds.EVENT_ENGINE_SIGNATURE_OPERATION_FAILURE,
        auditLogger.getEvents().get(0).getId());
    Assertions.assertEquals(SignServiceErrorCode.REQUEST_INCORRECT.name(),
        auditLogger.getEvents().get(0).getParameters().stream().filter(p -> "error-code".equals(p.getName()))
            .map(AuditEventParameter::getValue).findFirst().orElse(null));
  }

  @Test
  public void testProcessSignRequestNoAuthnRedirect() throws Exception {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    final AuthenticationResult ar = mock(AuthenticationResult.class);
    when(ar.signMessageDisplayed()).thenReturn(true);
    when(ar.getAssertion()).thenAnswer(e -> {
      return this.setupIdentityAssertion();
    });
    when(this.authnHandler.authenticate(any(), any(), any())).thenReturn(new AuthenticationResultChoice(ar));

    final SignServiceProcessingResult result = engine.processRequest(this.httpRequest, this.httpResponse, null);
    Assertions.assertNotNull(result);
    Assertions.assertNull(result.getSignServiceContext());
    Assertions.assertEquals("SUCCESS", result.getHttpRequestMessage().getHttpParameters().get("result-code"));
  }

  @Test
  public void testProcessSignRequestInitAuthnFailedCancel() throws Exception {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    when(this.authnHandler.authenticate(any(), any(), any())).thenThrow(
        new UserAuthenticationException(AuthenticationErrorCode.USER_CANCEL, "msg"));

    final SignServiceProcessingResult result = engine.processRequest(this.httpRequest, this.httpResponse, null);
    Assertions.assertNotNull(result);
    Assertions.assertNull(result.getSignServiceContext());
    Assertions.assertEquals(SignServiceErrorCode.AUTHN_USER_CANCEL.name(),
        result.getHttpRequestMessage().getHttpParameters().get("result-code"));
  }

  @Test
  public void testProcessSignRequestResumeAuthnFailedCancel() throws Exception {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    SignServiceProcessingResult result = engine.processRequest(this.httpRequest, this.httpResponse, null);

    when(this.httpRequest.getServletPath()).thenReturn(SAML_POST_PATH);
    when(this.authnHandler.resumeAuthentication(any(), any())).thenThrow(
        new UserAuthenticationException(AuthenticationErrorCode.USER_CANCEL, "msg"));

    result = engine.processRequest(this.httpRequest, this.httpResponse, result.getSignServiceContext());
    Assertions.assertNull(result.getSignServiceContext());
    Assertions.assertEquals(SignServiceErrorCode.AUTHN_USER_CANCEL.name(),
        result.getHttpRequestMessage().getHttpParameters().get("result-code"));
  }

  @Test
  public void testProcessSignRequestInitAuthnFailedUnsupportedAuthnContext() throws Exception {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    when(this.authnHandler.authenticate(any(), any(), any())).thenThrow(
        new UserAuthenticationException(AuthenticationErrorCode.UNSUPPORTED_AUTHNCONTEXT, "msg"));

    final SignServiceProcessingResult result = engine.processRequest(this.httpRequest, this.httpResponse, null);
    Assertions.assertEquals(SignServiceErrorCode.AUTHN_UNSUPPORTED_AUTHNCONTEXT.name(),
        result.getHttpRequestMessage().getHttpParameters().get("result-code"));
  }

  @Test
  public void testProcessSignRequestInitAuthnFailedMismatch() throws Exception {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    when(this.authnHandler.authenticate(any(), any(), any())).thenThrow(
        new UserAuthenticationException(AuthenticationErrorCode.MISMATCHING_IDENTITY_ATTRIBUTES, "msg"));

    final SignServiceProcessingResult result = engine.processRequest(this.httpRequest, this.httpResponse, null);
    Assertions.assertEquals(SignServiceErrorCode.AUTHN_USER_MISMATCH.name(),
        result.getHttpRequestMessage().getHttpParameters().get("result-code"));
  }

  @Test
  public void testProcessSignRequestInitAuthnFailedGeneral() throws Exception {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    when(this.authnHandler.authenticate(any(), any(), any())).thenThrow(
        new UserAuthenticationException(AuthenticationErrorCode.FAILED_AUTHN, "msg"));

    final SignServiceProcessingResult result = engine.processRequest(this.httpRequest, this.httpResponse, null);
    Assertions.assertEquals(SignServiceErrorCode.AUTHN_FAILURE.name(),
        result.getHttpRequestMessage().getHttpParameters().get("result-code"));
  }

  @Test
  public void testCanProcessSignRequest() {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    Assertions.assertTrue(engine.canProcess(this.httpRequest));
  }

  @Test
  public void testCanProcessMetadata() {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    when(this.httpRequest.getServletPath()).thenReturn(METADATA_PATH);

    Assertions.assertTrue(engine.canProcess(this.httpRequest));
  }

  @Test
  public void testCanProcessFalse() {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    when(this.httpRequest.getServletPath()).thenReturn("/other");

    Assertions.assertFalse(engine.canProcess(this.httpRequest));
  }

  @Test
  public void testCanProcessTrue() {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    when(this.httpRequest.getServletPath()).thenReturn("/other");

    final HttpResourceProvider p = mock(HttpResourceProvider.class);
    when(p.supports(any())).thenReturn(true);
    when(this.engineConfiguration.getHttpResourceProviders()).thenReturn(List.of(p));

    Assertions.assertTrue(engine.canProcess(this.httpRequest));
  }

  @Test
  public void testServeResource() throws Exception {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    when(this.httpRequest.getServletPath()).thenReturn(RESOURCE_PATH);
    final SignServiceProcessingResult result = engine.processRequest(this.httpRequest, this.httpResponse, null);
    Assertions.assertNull(result.getHttpRequestMessage());
  }

  @Test
  public void testServeResourceError() throws Exception {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    when(this.httpRequest.getServletPath()).thenReturn(ERROR_RESOURCE_PATH);

    assertThatThrownBy(() -> {
      engine.processRequest(this.httpRequest, this.httpResponse, null);
    }).isInstanceOf(UnrecoverableSignServiceException.class)
        .hasMessage("Failed to get resource")
        .extracting((e) -> UnrecoverableSignServiceException.class.cast(e).getErrorCode())
        .isEqualTo(UnrecoverableErrorCodes.HTTP_GET_ERROR);
  }

  @Test
  public void testStateError() throws Exception {
    final DefaultSignServiceEngine engine = new DefaultSignServiceEngine(
        this.engineConfiguration, this.messageReplayChecker, this.systemAuditLogger);
    engine.setSignRequestMessageVerifier(this.signRequestMessageVerifier);

    when(this.httpRequest.getServletPath()).thenReturn(SAML_POST_PATH);

    assertThatThrownBy(() -> {
      engine.processRequest(this.httpRequest, this.httpResponse, null);
    }).isInstanceOf(UnrecoverableSignServiceException.class)
        .hasMessage("State error - did not expect message")
        .extracting((e) -> UnrecoverableSignServiceException.class.cast(e).getErrorCode())
        .isEqualTo(UnrecoverableErrorCodes.STATE_ERROR);
  }

  // For testing audit logging
  private static class TestAuditLogger extends AbstractAuditLogger {

    @Getter
    private final List<AuditEvent> events = new ArrayList<>();

    @Override
    public void auditLog(@Nonnull final AuditEvent event) throws AuditLoggerException {
      this.events.add(event);
    }

  }

  private static class MockSignResponseMessage implements SignResponseMessage {

    /**
     *
     */
    private static final long serialVersionUID = -2731704857543021751L;
    private SignResponseResult signResponseResult;

    @Override
    public ProtocolProcessingRequirements getProcessingRequirements() {
      return new ProtocolProcessingRequirements() {

        /**
         *
         */
        private static final long serialVersionUID = -1298211123983018704L;

        @Override
        public SignatureRequirement getRequestSignatureRequirement() {
          return SignatureRequirement.REQUIRED;
        }

        @Override
        public SignatureRequirement getResponseSignatureRequirement() {
          return SignatureRequirement.REQUIRED;
        }

        @Override
        public String getResponseSendMethod() {
          return "POST";
        }

      };
    }

    @Override
    public SignResponseResult getSignResponseResult() {
      return this.signResponseResult != null
          ? this.signResponseResult
          : new SignResponseResult() {

            /**
             *
             */
            private static final long serialVersionUID = -3651280821612500502L;

            @Override
            public boolean isSuccess() {
              return true;
            }

            @Override
            public String getMinorErrorCode() {
              return null;
            }

            @Override
            public String getMessage() {
              return "Success";
            }

            @Override
            public String getErrorCode() {
              return null;
            }
          };
    }

    @Override
    public void setSignResponseResult(final SignResponseResult signResponseResult) {
      this.signResponseResult = signResponseResult;
    }

    @Override
    public void sign(final PkiCredential signatureCredential) throws SignatureException {
    }

    @Override
    public String encode() throws ProtocolException {
      return "ENCODING";
    }

    @Override
    public void setRelayState(final String relayState) {
    }

    @Override
    public String getRelayState() {
      return null;
    }

    @Override
    public String getInResponseTo() {
      return null;
    }

    @Override
    public void setInResponseTo(final String requestId) {
    }

    @Override
    public Instant getIssuedAt() {
      return null;
    }

    @Override
    public void setIssuedAt(final Instant issuedAt) {
    }

    @Override
    public String getIssuerId() {
      return null;
    }

    @Override
    public void setIssuerId(final String issuerId) {
    }

    @Override
    public String getDestinationUrl() {
      return null;
    }

    @Override
    public void setDestinationUrl(final String destinationUrl) {
    }

    @Override
    public SignerAuthnInfo getSignerAuthnInfo() {
      return null;
    }

    @Override
    public void setSignerAuthnInfo(final SignerAuthnInfo signerAuthnInfo) {
    }

    @Override
    public List<X509Certificate> getSignatureCertificateChain() {
      return null;
    }

    @Override
    public void setSignatureCertificateChain(final List<X509Certificate> chain) {
    }

    @Override
    public List<CompletedSignatureTask> getSignatureTasks() {
      return null;
    }

    @Override
    public void setSignatureTasks(final List<CompletedSignatureTask> signatureTasks) {
    }

  }

}
