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
package se.swedenconnect.signservice.authn.saml;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.ext.saml2mdattr.EntityAttributes;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusMessage;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.w3c.dom.Element;

import net.shibboleth.shared.resolver.ResolverException;
import se.idsec.signservice.xml.DOMUtils;
import se.swedenconnect.opensaml.saml2.attribute.AttributeBuilder;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.saml2.request.RequestHttpObject;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingException;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingResult;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessor;
import se.swedenconnect.opensaml.saml2.response.ResponseStatusErrorException;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.LevelOfAssuranceUris;
import se.swedenconnect.signservice.authn.AuthenticationErrorCode;
import se.swedenconnect.signservice.authn.AuthenticationResultChoice;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.authn.UserAuthenticationException;
import se.swedenconnect.signservice.authn.impl.SimpleAuthnContextIdentifier;
import se.swedenconnect.signservice.authn.saml.config.SpUrlConfiguration;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;
import se.swedenconnect.signservice.core.http.HttpBodyAction;
import se.swedenconnect.signservice.core.http.HttpUserRequest;
import se.swedenconnect.signservice.protocol.msg.AuthnRequirements;
import se.swedenconnect.signservice.protocol.msg.SignMessage;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultAuthnRequirements;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultSignatureActivationRequestData;

/**
 * Test cases for DefaultSamlAuthenticationHandler.
 */
public class DefaultSamlAuthenticationHandlerTest extends OpenSamlTestBase {

  protected static final String CONTEXT_ID = "ID";
  protected static final String SIGNREQUEST_ID = "SR-ID";

  protected static final String IDP = "https://idp.example.com";
  protected static final String IDP_DESTINATION = "https://idp.example.com/sso";

  protected static final String PNR = "197501015817";

  protected static final String GN1 = "Kalle";
  protected static final String GN2 = "Bosse";
  protected static final String SN = "Kula";

  protected static final String ASSERTION_CONSUMER_PATH = "/saml/response";
  protected static final String METADATA_PATH = "/metadata";

  protected final AuthnRequestGenerator authnRequestGenerator = Mockito.mock(AuthnRequestGenerator.class);

  protected final ResponseProcessor responseProcessor = Mockito.mock(ResponseProcessor.class);

  protected final MetadataProvider metadataProvider = Mockito.mock(MetadataProvider.class);

  protected final EntityDescriptorContainer entityDescriptorContainer = Mockito.mock(EntityDescriptorContainer.class);

  protected final SpUrlConfiguration spUrlConfiguration = Mockito.mock(SpUrlConfiguration.class);

  protected final SignServiceContext context = Mockito.mock(SignServiceContext.class);

  protected final EntityDescriptor idpMetadata = Mockito.mock(EntityDescriptor.class);

  protected AbstractSamlAuthenticationHandler handler;

  protected AbstractSamlAuthenticationHandler createHandler() {
    return new DefaultSamlAuthenticationHandler(this.authnRequestGenerator, this.responseProcessor,
        this.metadataProvider, this.entityDescriptorContainer, this.spUrlConfiguration);
  }

  @BeforeEach
  public void setup() throws Exception {
    this.handler = this.createHandler();

    Mockito.when(this.context.getId()).thenReturn(CONTEXT_ID);

    Mockito
        .when(this.metadataProvider.getEntityDescriptor(eq(IDP), eq(IDPSSODescriptor.DEFAULT_ELEMENT_NAME)))
        .thenReturn(this.idpMetadata);

    Mockito.when(this.idpMetadata.getEntityID()).thenReturn(IDP);

    final Extensions extensions = (Extensions) XMLObjectSupport.buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
    final Attribute attribute =
        AttributeBuilder
            .builder(
                se.swedenconnect.opensaml.saml2.attribute.AttributeConstants.ASSURANCE_CERTIFICATION_ATTRIBUTE_NAME)
            .value(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3)
            .build();
    final EntityAttributes ea =
        (EntityAttributes) XMLObjectSupport.buildXMLObject(EntityAttributes.DEFAULT_ELEMENT_NAME);
    ea.getAttributes().add(attribute);
    extensions.getUnknownXMLObjects().add(ea);
    Mockito.when(this.idpMetadata.getExtensions()).thenReturn(extensions);

    Mockito.when(this.spUrlConfiguration.getBaseUrl()).thenReturn("https://www.example.com/sp");
    Mockito.when(this.spUrlConfiguration.getAssertionConsumerPath()).thenReturn(ASSERTION_CONSUMER_PATH);
    Mockito.when(this.spUrlConfiguration.getAdditionalAssertionConsumerPath()).thenReturn(null);
    Mockito.when(this.spUrlConfiguration.getMetadataPublishingPath()).thenReturn(METADATA_PATH);
  }

  @Test
  public void testName() {
    Assertions.assertEquals("DefaultSamlAuthenticationHandler", this.handler.getName());

    this.handler.setName("Handler");
    Assertions.assertEquals("Handler", this.handler.getName());
  }

  @Test
  public void testAuthenticateSuccess() throws Exception {
    final AuthnRequirements authnReqs = this.getAuthnRequirements();

    @SuppressWarnings("unchecked")
    final RequestHttpObject<AuthnRequest> requestObject = Mockito.mock(RequestHttpObject.class);
    Mockito.when(requestObject.getRequest()).thenReturn(this.getAuthnRequest());
    Mockito.when(requestObject.getMethod()).thenReturn("POST");
    Mockito.when(requestObject.getSendUrl()).thenReturn(IDP_DESTINATION);
    Mockito.when(requestObject.getRequestParameters()).thenReturn(new HashMap<>() {
      private static final long serialVersionUID = 1L;

      {
        this.put("SAMLRequest", "ENCODED_REQUEST");
        this.put("RelayState", CONTEXT_ID);
      }
    });
    Mockito.when(this.authnRequestGenerator.generateAuthnRequest(eq(IDP), anyString(), any()))
        .thenAnswer((a) -> {
          final AuthnRequestGeneratorContext ctx = a.getArgument(2, AuthnRequestGeneratorContext.class);
          ctx.getAuthnRequestCustomizer();
          ctx.getAssertionConsumerServiceResolver();
          ctx.getRequestedAuthnContextBuilderFunction();
          return requestObject;
        });

    final AuthenticationResultChoice result = this.handler.authenticate(authnReqs, null, this.context);

    Assertions.assertNull(result.getAuthenticationResult());
    Assertions.assertNotNull(result.getResponseAction().getPost());
    Assertions.assertEquals(IDP_DESTINATION, result.getResponseAction().getPost().getUrl());
    Assertions.assertNotNull(result.getResponseAction().getPost().getParameters().get("SAMLRequest"));

    Mockito.verify(this.context).put(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY),
        ArgumentMatchers.notNull());
    Mockito.verify(this.context).put(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY), eq("ID"));
    Mockito.verify(this.context).put(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY), eq(authnReqs));
    Mockito.verify(this.context, Mockito.never()).put(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY), any());
  }

  @Test
  public void testAuthenticateNotSupportedAuthnCtx() throws Exception {
    final AuthnRequirements authnReqs = this.getAuthnRequirements();
    ((DefaultAuthnRequirements) authnReqs).setAuthnContextIdentifiers(List.of(
        new SimpleAuthnContextIdentifier(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2)));

    @SuppressWarnings("unchecked")
    final RequestHttpObject<AuthnRequest> requestObject = Mockito.mock(RequestHttpObject.class);
    Mockito.when(requestObject.getRequest()).thenReturn(this.getAuthnRequest());
    Mockito.when(requestObject.getMethod()).thenReturn("POST");
    Mockito.when(requestObject.getSendUrl()).thenReturn(IDP_DESTINATION);
    Mockito.when(requestObject.getRequestParameters()).thenReturn(new HashMap<>() {
      private static final long serialVersionUID = 1L;

      {
        this.put("SAMLRequest", "ENCODED_REQUEST");
        this.put("RelayState", CONTEXT_ID);
      }
    });
    Mockito.when(this.authnRequestGenerator.generateAuthnRequest(eq(IDP), anyString(), any()))
        .thenAnswer((a) -> {
          final AuthnRequestGeneratorContext ctx = a.getArgument(2, AuthnRequestGeneratorContext.class);
          ctx.getAuthnRequestCustomizer();
          ctx.getAssertionConsumerServiceResolver();
          ctx.getRequestedAuthnContextBuilderFunction();
          return requestObject;
        });

    assertThatThrownBy(() -> {
      this.handler.authenticate(authnReqs, null, this.context);
    }).isInstanceOf(UserAuthenticationException.class)
        .hasMessage("None of the requested authn context URIs are supported by the IdP");

  }

  @Test
  public void testAuthenticateSadError() throws Exception {
    final AuthnRequirements authnReqs = this.getAuthnRequirements();
    ((DefaultAuthnRequirements) authnReqs).setSignatureActivationRequestData(
        new DefaultSignatureActivationRequestData(SIGNREQUEST_ID, 2, true));

    final SignMessage sm = Mockito.mock(SignMessage.class);

    assertThatThrownBy(() -> {
      this.handler.authenticate(authnReqs, sm, this.context);
    }).isInstanceOf(UserAuthenticationException.class)
        .hasMessage("Authentication requirements states that a SAD request should be sent "
            + "but the IdP does not support the Signature Activation Data extension");
  }

  @Test
  public void testAuthenticateSignMessageNotSupported() {
    final SignMessage sm = Mockito.mock(SignMessage.class);
    Mockito.when(sm.getMustShow()).thenReturn(true);

    try {
      this.handler.authenticate(this.getAuthnRequirements(), sm, this.context);
      Assertions.fail("Expected UserAuthenticationException");
    }
    catch (final UserAuthenticationException e) {
      Assertions.assertEquals(AuthenticationErrorCode.FAILED_AUTHN, e.getErrorCode());
    }
  }

  @Test
  public void testAuthenticateNoIdP() throws Exception {
    final AuthnRequirements authnReqs = this.getAuthnRequirements();

    Mockito.when(this.metadataProvider.getEntityDescriptor(eq(IDP), eq(IDPSSODescriptor.DEFAULT_ELEMENT_NAME)))
        .thenReturn(null);

    try {
      this.handler.authenticate(authnReqs, null, this.context);
      Assertions.fail("Expected UserAuthenticationException");
    }
    catch (final UserAuthenticationException e) {
      Assertions.assertEquals(AuthenticationErrorCode.UNKNOWN_AUTHENTICATION_SERVICE, e.getErrorCode());
    }

    Mockito.when(this.metadataProvider.getEntityDescriptor(eq(IDP), eq(IDPSSODescriptor.DEFAULT_ELEMENT_NAME)))
        .thenThrow(new ResolverException("resolver error"));
    try {
      this.handler.authenticate(authnReqs, null, this.context);
      Assertions.fail("Expected UserAuthenticationException");
    }
    catch (final UserAuthenticationException e) {
      Assertions.assertEquals(AuthenticationErrorCode.UNKNOWN_AUTHENTICATION_SERVICE, e.getErrorCode());
    }

    ((DefaultAuthnRequirements) authnReqs).setAuthnServiceID(null);
    try {
      this.handler.authenticate(authnReqs, null, this.context);
      Assertions.fail("Expected UserAuthenticationException");
    }
    catch (final UserAuthenticationException e) {
      Assertions.assertEquals(AuthenticationErrorCode.UNKNOWN_AUTHENTICATION_SERVICE, e.getErrorCode());
      Assertions.assertEquals("No Identity Provider entityID supplied in requirements", e.getMessage());
    }
  }

  @Test
  public void testCanProcess() {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn(ASSERTION_CONSUMER_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn("response");

    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY)))
        .thenReturn("ENCODED_AUTHNREQUEST");

    Assertions.assertTrue(this.handler.canProcess(request, this.context));
    Assertions.assertTrue(this.handler.canProcess(request, null));
  }

  @Test
  public void testCanProcessMatchAdditional() {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn(ASSERTION_CONSUMER_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn("response");

    Mockito.when(this.spUrlConfiguration.getAdditionalAssertionConsumerPath()).thenReturn("/saml/response2");

    Assertions.assertTrue(this.handler.canProcess(request, null));
  }

  @Test
  public void testCanProcessMismatchingPath() {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn("/saml/other");
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn("response");

    Assertions.assertFalse(this.handler.canProcess(request, null));
  }

  @Test
  public void testCanProcessBadMethod() {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn("response");

    Assertions.assertFalse(this.handler.canProcess(request, null));
  }

  @Test
  public void testCanProcessMissingResponse() {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn(null);

    Assertions.assertFalse(this.handler.canProcess(request, null));
  }

  @Test
  public void testCanProcessMissingAuthnRequest() {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn(ASSERTION_CONSUMER_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn("response");

    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY)))
        .thenReturn(null);

    Assertions.assertFalse(this.handler.canProcess(request, this.context));
  }

  @Test
  public void testResumeAuthentication() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn(ASSERTION_CONSUMER_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn("SAML-RESPONSE");
    Mockito.when(request.getParameter(eq("RelayState"))).thenReturn(CONTEXT_ID);

    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY), any()))
        .thenReturn(this.getEncodedAuthnRequest());
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY), any()))
        .thenReturn(CONTEXT_ID);
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY), any()))
        .thenReturn(null);
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY), any()))
        .thenReturn(this.getAuthnRequirements());

    final ResponseProcessingResult processingResult = Mockito.mock(ResponseProcessingResult.class);
    Mockito.when(processingResult.getAttributes()).thenReturn(
        Arrays.asList(
            AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
                .friendlyName(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER)
                .value(PNR)
                .build(),
            AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME)
                .friendlyName(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME)
                .value(GN2)
                .build(),
            AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_SN)
                .friendlyName(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_SN)
                .value(SN)
                .build()));
    Mockito.when(processingResult.getAuthnContextClassUri()).thenReturn(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3);
    Mockito.when(processingResult.getAssertion()).thenReturn(this.getAssertion());
    Mockito.when(processingResult.getIssuer()).thenReturn(IDP);

    final Instant issuanceInstant = Instant.now().minusMillis(500L);
    Mockito.when(processingResult.getIssueInstant()).thenReturn(issuanceInstant);

    final Instant authnInstant = Instant.now().minusMillis(1000L);
    Mockito.when(processingResult.getAuthnInstant()).thenReturn(authnInstant);

    Mockito.when(this.responseProcessor.processSamlResponse(anyString(), anyString(), any(), any()))
        .thenReturn(processingResult);

    final AuthenticationResultChoice result = this.handler.resumeAuthentication(request, this.context);

    Assertions.assertNull(result.getResponseAction());
    Assertions.assertNotNull(result.getAuthenticationResult());
    Assertions.assertFalse(result.getAuthenticationResult().signMessageDisplayed());
    final IdentityAssertion assertion = result.getAuthenticationResult().getAssertion();
    Assertions.assertNotNull(assertion.getIdentifier());
    Assertions.assertEquals(IDP, assertion.getIssuer());
    Assertions.assertEquals(issuanceInstant, assertion.getIssuanceInstant());
    Assertions.assertNotNull(assertion.getEncodedAssertion());

    Assertions.assertTrue(assertion.getIdentityAttributes().stream()
        .filter(a -> AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER.equals(a.getIdentifier()))
        .findFirst()
        .isPresent());
    Assertions.assertTrue(assertion.getIdentityAttributes().stream()
        .filter(a -> AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME.equals(a.getIdentifier()))
        .findFirst()
        .isPresent());
    Assertions.assertTrue(assertion.getIdentityAttributes().stream()
        .filter(a -> AttributeConstants.ATTRIBUTE_NAME_SN.equals(a.getIdentifier()))
        .findFirst()
        .isPresent());

    // Assert that the context was cleaned
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY));
  }

  @Test
  public void testResumeAuthenticationCantProcess() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn(ASSERTION_CONSUMER_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn(null);

    Assertions.assertThrows(UserAuthenticationException.class, () -> {
      this.handler.resumeAuthentication(request, this.context);
    });
  }

  @Test
  public void testResumeAuthenticationNoAuthnRequest() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn(ASSERTION_CONSUMER_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn("SAML-RESPONSE");
    Mockito.when(request.getParameter(eq("RelayState"))).thenReturn(CONTEXT_ID);

    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY), any()))
        .thenReturn(null);

    Assertions.assertThrows(UserAuthenticationException.class, () -> {
      this.handler.resumeAuthentication(request, this.context);
    });

    // Assert that the context was cleaned
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY));
  }

  @Test
  public void testResumeAuthenticationUserCancel() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn(ASSERTION_CONSUMER_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn("SAML-RESPONSE");
    Mockito.when(request.getParameter(eq("RelayState"))).thenReturn(CONTEXT_ID);

    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY), any()))
        .thenReturn(this.getEncodedAuthnRequest());
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY), any()))
        .thenReturn(CONTEXT_ID);
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY), any()))
        .thenReturn(null);
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY), any()))
        .thenReturn(this.getAuthnRequirements());

    final Status status = (Status) XMLObjectSupport.buildXMLObject(Status.DEFAULT_ELEMENT_NAME);
    final StatusCode outerCode = (StatusCode) XMLObjectSupport.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
    outerCode.setValue(StatusCode.RESPONDER);
    final StatusCode innerCode = (StatusCode) XMLObjectSupport.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
    innerCode.setValue(SamlStatus.CANCEL_STATUS_CODE);
    outerCode.setStatusCode(innerCode);
    status.setStatusCode(outerCode);
    final StatusMessage message = (StatusMessage) XMLObjectSupport.buildXMLObject(StatusMessage.DEFAULT_ELEMENT_NAME);
    message.setValue("THE_STATUS_MESSAGE");
    status.setStatusMessage(message);
    final ResponseStatusErrorException statusException = new ResponseStatusErrorException(status, "id", "issuer");

    Mockito.when(this.responseProcessor.processSamlResponse(anyString(), anyString(), any(), any()))
        .thenThrow(statusException);

    try {
      this.handler.resumeAuthentication(request, this.context);
      Assertions.fail("Expected UserAuthenticationException");
    }
    catch (final UserAuthenticationException e) {
      Assertions.assertEquals(AuthenticationErrorCode.USER_CANCEL, e.getErrorCode());
    }

    // Assert that the context was cleaned
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY));
  }

  @Test
  public void testResumeAuthenticationNoIdP() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn(ASSERTION_CONSUMER_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn("SAML-RESPONSE");
    Mockito.when(request.getParameter(eq("RelayState"))).thenReturn(CONTEXT_ID);

    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY), any()))
        .thenReturn(this.getEncodedAuthnRequest());
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY), any()))
        .thenReturn(CONTEXT_ID);
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY), any()))
        .thenReturn(null);
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY), any()))
        .thenReturn(this.getAuthnRequirements());

    final Status status = (Status) XMLObjectSupport.buildXMLObject(Status.DEFAULT_ELEMENT_NAME);
    final StatusCode outerCode = (StatusCode) XMLObjectSupport.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
    outerCode.setValue(StatusCode.RESPONDER);
    final StatusCode innerCode = (StatusCode) XMLObjectSupport.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
    innerCode.setValue(StatusCode.NO_SUPPORTED_IDP);
    outerCode.setStatusCode(innerCode);
    status.setStatusCode(outerCode);
    final StatusMessage message = (StatusMessage) XMLObjectSupport.buildXMLObject(StatusMessage.DEFAULT_ELEMENT_NAME);
    message.setValue("THE_STATUS_MESSAGE");
    status.setStatusMessage(message);
    final ResponseStatusErrorException statusException = new ResponseStatusErrorException(status, "id", "issuer");

    Mockito.when(this.responseProcessor.processSamlResponse(anyString(), anyString(), any(), any()))
        .thenThrow(statusException);

    try {
      this.handler.resumeAuthentication(request, this.context);
      Assertions.fail("Expected UserAuthenticationException");
    }
    catch (final UserAuthenticationException e) {
      Assertions.assertEquals(AuthenticationErrorCode.UNKNOWN_AUTHENTICATION_SERVICE, e.getErrorCode());
      Assertions.assertEquals("THE_STATUS_MESSAGE", e.getMessage());
    }
  }

  @Test
  public void testResumeAuthenticationNoAuthnContext() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn(ASSERTION_CONSUMER_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn("SAML-RESPONSE");
    Mockito.when(request.getParameter(eq("RelayState"))).thenReturn(CONTEXT_ID);

    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY), any()))
        .thenReturn(this.getEncodedAuthnRequest());
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY), any()))
        .thenReturn(CONTEXT_ID);
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY), any()))
        .thenReturn(null);
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY), any()))
        .thenReturn(this.getAuthnRequirements());

    final Status status = (Status) XMLObjectSupport.buildXMLObject(Status.DEFAULT_ELEMENT_NAME);
    final StatusCode outerCode = (StatusCode) XMLObjectSupport.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
    outerCode.setValue(StatusCode.RESPONDER);
    final StatusCode innerCode = (StatusCode) XMLObjectSupport.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
    innerCode.setValue(StatusCode.NO_AUTHN_CONTEXT);
    outerCode.setStatusCode(innerCode);
    status.setStatusCode(outerCode);
    final StatusMessage message = (StatusMessage) XMLObjectSupport.buildXMLObject(StatusMessage.DEFAULT_ELEMENT_NAME);
    message.setValue("THE_STATUS_MESSAGE");
    status.setStatusMessage(message);
    final ResponseStatusErrorException statusException = new ResponseStatusErrorException(status, "id", "issuer");

    Mockito.when(this.responseProcessor.processSamlResponse(anyString(), anyString(), any(), any()))
        .thenThrow(statusException);

    try {
      this.handler.resumeAuthentication(request, this.context);
      Assertions.fail("Expected UserAuthenticationException");
    }
    catch (final UserAuthenticationException e) {
      Assertions.assertEquals(AuthenticationErrorCode.UNSUPPORTED_AUTHNCONTEXT, e.getErrorCode());
      Assertions.assertEquals("THE_STATUS_MESSAGE", e.getMessage());
    }

    // Assert that the context was cleaned
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY));
  }

  @Test
  public void testResumeAuthenticationFailedAuthn() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn(ASSERTION_CONSUMER_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn("SAML-RESPONSE");
    Mockito.when(request.getParameter(eq("RelayState"))).thenReturn(CONTEXT_ID);

    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY), any()))
        .thenReturn(this.getEncodedAuthnRequest());
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY), any()))
        .thenReturn(CONTEXT_ID);
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY), any()))
        .thenReturn(null);
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY), any()))
        .thenReturn(this.getAuthnRequirements());

    final Status status = (Status) XMLObjectSupport.buildXMLObject(Status.DEFAULT_ELEMENT_NAME);
    final StatusCode outerCode = (StatusCode) XMLObjectSupport.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
    outerCode.setValue(StatusCode.RESPONDER);
    final StatusCode innerCode = (StatusCode) XMLObjectSupport.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
    innerCode.setValue(StatusCode.AUTHN_FAILED);
    outerCode.setStatusCode(innerCode);
    status.setStatusCode(outerCode);
    final StatusMessage message = (StatusMessage) XMLObjectSupport.buildXMLObject(StatusMessage.DEFAULT_ELEMENT_NAME);
    message.setValue("THE_STATUS_MESSAGE");
    status.setStatusMessage(message);
    final ResponseStatusErrorException statusException = new ResponseStatusErrorException(status, "id", "issuer");

    Mockito.when(this.responseProcessor.processSamlResponse(anyString(), anyString(), any(), any()))
        .thenThrow(statusException);

    try {
      this.handler.resumeAuthentication(request, this.context);
      Assertions.fail("Expected UserAuthenticationException");
    }
    catch (final UserAuthenticationException e) {
      Assertions.assertEquals(AuthenticationErrorCode.FAILED_AUTHN, e.getErrorCode());
      Assertions.assertEquals(
          "Authentication failure: THE_STATUS_MESSAGE (urn:oasis:names:tc:SAML:2.0:status:AuthnFailed)",
          e.getMessage());
    }

    // Assert that the context was cleaned
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY));
  }

  @Test
  public void testResumeAuthenticationProcessingError() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn(ASSERTION_CONSUMER_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn("SAML-RESPONSE");
    Mockito.when(request.getParameter(eq("RelayState"))).thenReturn(CONTEXT_ID);

    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY), any()))
        .thenReturn(this.getEncodedAuthnRequest());
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY), any()))
        .thenReturn(CONTEXT_ID);
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY), any()))
        .thenReturn(null);
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY), any()))
        .thenReturn(this.getAuthnRequirements());

    Mockito.when(this.responseProcessor.processSamlResponse(anyString(), anyString(), any(), any()))
        .thenThrow(new ResponseProcessingException("ERROR_MSG"));

    try {
      this.handler.resumeAuthentication(request, this.context);
      Assertions.fail("Expected UserAuthenticationException");
    }
    catch (final UserAuthenticationException e) {
      Assertions.assertEquals(AuthenticationErrorCode.FAILED_AUTHN, e.getErrorCode());
      Assertions.assertEquals("Error processing SAML response - ERROR_MSG", e.getMessage());
    }

    // Assert that the context was cleaned
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY));
  }

  @Test
  public void testSupports() {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn(METADATA_PATH);
    Mockito.when(request.getMethod()).thenReturn("GET");

    Assertions.assertTrue(this.handler.supports(request));
  }

  @Test
  public void testSupportsBadMethod() {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn(METADATA_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");

    Assertions.assertFalse(this.handler.supports(request));
  }

  @Test
  public void testSupportsBadPath() {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn("/other");
    Mockito.when(request.getMethod()).thenReturn("GET");

    Assertions.assertFalse(this.handler.supports(request));
  }

  @Test
  public void testGetResource() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn(METADATA_PATH);
    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getHeader(eq("Accept"))).thenReturn(null);

    Mockito.when(this.entityDescriptorContainer.updateRequired(anyBoolean())).thenReturn(true);
    Mockito.when(this.entityDescriptorContainer.marshall()).thenReturn(this.getEntityDescriptorElement());

    final HttpBodyAction action = this.handler.getResource(request);

    Mockito.verify(this.entityDescriptorContainer).update(anyBoolean());

    Assertions.assertNotNull(action.getContents());
    Assertions.assertEquals("application/xml", action.getHeaders().get("Content-Type"));
  }

  @Test
  public void testGetResourceNotUpdated() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn(METADATA_PATH);
    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getHeader(eq("Accept")))
        .thenReturn(AbstractSamlAuthenticationHandler.APPLICATION_SAML_METADATA);

    Mockito.when(this.entityDescriptorContainer.updateRequired(anyBoolean())).thenReturn(false);
    Mockito.when(this.entityDescriptorContainer.marshall()).thenReturn(this.getEntityDescriptorElement());

    final HttpBodyAction action = this.handler.getResource(request);

    Mockito.verify(this.entityDescriptorContainer, never()).update(anyBoolean());

    Assertions.assertNotNull(action.getContents());
    Assertions.assertEquals(AbstractSamlAuthenticationHandler.APPLICATION_SAML_METADATA,
        action.getHeaders().get("Content-Type"));
  }

  @Test
  public void testGetResourceFailed() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn(METADATA_PATH);
    Mockito.when(request.getMethod()).thenReturn("GET");
    Mockito.when(request.getHeader(eq("Accept"))).thenReturn(null);

    Mockito.when(this.entityDescriptorContainer.updateRequired(anyBoolean())).thenReturn(true);
    Mockito.when(this.entityDescriptorContainer.update(anyBoolean()))
        .thenThrow(new org.opensaml.xmlsec.signature.support.SignatureException("error"));

    Assertions.assertThrows(IOException.class, () -> {
      this.handler.getResource(request);
    });
  }

  @Test
  public void testGetResourceSupportsFails() throws Exception {
    final HttpUserRequest request = Mockito.mock(HttpUserRequest.class);
    Mockito.when(request.getServerServletPath()).thenReturn(METADATA_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");

    Assertions.assertThrows(IOException.class, () -> {
      this.handler.getResource(request);
    });
  }

  protected AuthnRequirements getAuthnRequirements() {
    final DefaultAuthnRequirements reqs = new DefaultAuthnRequirements();
    reqs.setAuthnServiceID(IDP);
    reqs.setAuthnContextIdentifiers(Arrays.asList(
        new SimpleAuthnContextIdentifier(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3),
        new SimpleAuthnContextIdentifier(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3_NONRESIDENT)));
    reqs.setRequestedSignerAttributes(Arrays.asList(
        new StringSamlIdentityAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER, PNR),
        new StringSamlIdentityAttribute(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME, Arrays.asList(GN1, GN2)),
        new StringSamlIdentityAttribute(AttributeConstants.ATTRIBUTE_NAME_SN,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_SN, SN)));
    reqs.setSignatureActivationRequestData(
        new DefaultSignatureActivationRequestData(SIGNREQUEST_ID, 1, false));
    return reqs;
  }

  protected byte[] getEncodedAuthnRequest() throws Exception {
    final AuthnRequest authnRequest = this.getAuthnRequest();
    return DOMUtils.nodeToBytes(XMLObjectSupport.marshall(authnRequest));
  }

  protected AuthnRequest getAuthnRequest() throws Exception {
    final Element elm =
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/authnrequest.xml")).getDocumentElement();
    return (AuthnRequest) XMLObjectSupport.getUnmarshaller(elm).unmarshall(elm);
  }

  protected Assertion getAssertion() throws Exception {
    final Element elm =
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/assertion.xml")).getDocumentElement();
    return (Assertion) XMLObjectSupport.getUnmarshaller(elm).unmarshall(elm);
  }

  protected Element getEntityDescriptorElement() throws Exception {
    return DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/metadata.xml")).getDocumentElement();
  }
}
