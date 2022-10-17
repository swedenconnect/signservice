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
package se.swedenconnect.signservice.authn.saml;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.ext.saml2mdattr.EntityAttributes;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.w3c.dom.Element;

import se.idsec.signservice.xml.DOMUtils;
import se.swedenconnect.opensaml.saml2.attribute.AttributeBuilder;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGeneratorContext.AuthnRequestCustomizer;
import se.swedenconnect.opensaml.saml2.request.RequestHttpObject;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingResult;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessor;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.LevelOfAssuranceUris;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.PrincipalSelection;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.opensaml.sweid.saml2.request.SwedishEidAuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.sweid.saml2.signservice.SADParser.SADValidator;
import se.swedenconnect.opensaml.sweid.saml2.signservice.SADValidationException;
import se.swedenconnect.opensaml.sweid.saml2.signservice.SADValidationException.ErrorCode;
import se.swedenconnect.opensaml.sweid.saml2.signservice.sap.SAD;
import se.swedenconnect.signservice.authn.AuthenticationErrorCode;
import se.swedenconnect.signservice.authn.AuthenticationResultChoice;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.authn.UserAuthenticationException;
import se.swedenconnect.signservice.authn.saml.config.SpUrlConfiguration;
import se.swedenconnect.signservice.core.attribute.saml.impl.StringSamlIdentityAttribute;
import se.swedenconnect.signservice.protocol.msg.AuthnRequirements;
import se.swedenconnect.signservice.protocol.msg.SignMessage;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultAuthnRequirements;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultSignatureActivationRequestData;
import se.swedenconnect.signservice.session.SignServiceContext;

/**
 * Test cases for SwedenConnectSamlAuthenticationHandler.
 */
public class SwedenConnectSamlAuthenticationHandlerTest extends DefaultSamlAuthenticationHandlerTest {

  @Override
  protected AbstractSamlAuthenticationHandler createHandler() {
    return new SwedenConnectSamlAuthenticationHandler(this.authnRequestGenerator, this.responseProcessor,
        this.metadataProvider, this.entityDescriptorContainer, this.spUrlConfiguration);
  }

  @Override
  @Test
  public void testName() {
    final SwedenConnectSamlAuthenticationHandler handler =
        (SwedenConnectSamlAuthenticationHandler) this.createHandler();
    Assertions.assertEquals(SwedenConnectSamlAuthenticationHandler.class.getSimpleName(), handler.getName());

    handler.setName("Handler");
    Assertions.assertEquals("Handler", handler.getName());
  }

  @Test
  public void testAuthenticateSuccessWithSignMessage() throws Exception {
    final SwedenConnectSamlAuthenticationHandler handler =
        (SwedenConnectSamlAuthenticationHandler) this.createHandler();
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

    final SignMessage signMessage = Mockito.mock(SignMessage.class);
    Mockito.when(signMessage.getMustShow()).thenReturn(true);
    Mockito.when(signMessage.getEncoding()).thenReturn(this.getEncodedSignMessage());

    final AuthenticationResultChoice result = handler.authenticate(authnReqs, signMessage, this.context);

    Assertions.assertNull(result.getAuthenticationResult());
    Assertions.assertEquals("POST", result.getHttpRequestMessage().getMethod());
    Assertions.assertEquals(IDP_DESTINATION, result.getHttpRequestMessage().getUrl());
    Assertions.assertNotNull(result.getHttpRequestMessage().getHttpParameters().get("SAMLRequest"));

    Mockito.verify(this.context).put(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY),
        ArgumentMatchers.notNull());
    Mockito.verify(this.context).put(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY), eq("ID"));
    Mockito.verify(this.context).put(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY), eq(authnReqs));
    Mockito.verify(this.context).put(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY), ArgumentMatchers.notNull());
  }

  @Test
  public void testAuthenticateSuccessWithSignMessageUnknownMessage() throws Exception {
    final SwedenConnectSamlAuthenticationHandler handler =
        (SwedenConnectSamlAuthenticationHandler) this.createHandler();
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
          ctx.getAssertionConsumerServiceResolver();
          ctx.getRequestedAuthnContextBuilderFunction();
          ctx.getAuthnRequestCustomizer();
          return requestObject;
        });

    final SignMessage signMessage = Mockito.mock(SignMessage.class);
    Mockito.when(signMessage.getMustShow()).thenReturn(true);
    Mockito.when(signMessage.getEncoding()).thenReturn("not a sign message".getBytes());

    try {
      handler.authenticate(authnReqs, signMessage, this.context);
      Assertions.fail("Expected UserAuthenticationException");
    }
    catch (final UserAuthenticationException e) {
      Assertions.assertEquals(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR, e.getErrorCode());
    }
  }

  @Override
  @Test
  public void testAuthenticateSignMessageNotSupported() {
    // No-op
  }

  private void mockEntityCategories(final List<String> entityCategories) {

    Extensions exts = this.idpMetadata.getExtensions();
    EntityAttributes ea = null;
    if (exts != null) {
      ea = EntityDescriptorUtils.getMetadataExtension(exts, EntityAttributes.class);
    }
    else {
      exts = (Extensions) XMLObjectSupport.buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
    }
    if (ea == null) {
      ea = (EntityAttributes) XMLObjectSupport.buildXMLObject(EntityAttributes.DEFAULT_ELEMENT_NAME);
      exts.getUnknownXMLObjects().add(ea);
    }

    final Attribute entityCategoriesAttribute = AttributeBuilder.builder(
        se.swedenconnect.opensaml.saml2.attribute.AttributeConstants.ENTITY_CATEGORY_ATTRIBUTE_NAME)
        .value(entityCategories)
        .build();
    ea.getAttributes().add(entityCategoriesAttribute);

    Mockito.when(this.idpMetadata.getExtensions()).thenReturn(exts);
  }

  @Test
  public void testAuthenticateWithSadRequest() throws Exception {
    final SwedenConnectSamlAuthenticationHandler handler =
        (SwedenConnectSamlAuthenticationHandler) this.createHandler();
    final AuthnRequirements authnReqs = this.getAuthnRequirements();
    ((DefaultAuthnRequirements) authnReqs).setSignatureActivationRequestData(
        new DefaultSignatureActivationRequestData(SIGNREQUEST_ID, 1, true));

    this.mockEntityCategories(List.of(
        EntityCategoryConstants.SERVICE_PROPERTY_CATEGORY_SCAL2.getUri(),
        EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri()));

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
          ctx.getAssertionConsumerServiceResolver();
          ctx.getRequestedAuthnContextBuilderFunction();
          final AuthnRequestCustomizer customizer = ctx.getAuthnRequestCustomizer();
          final AuthnRequest ar = (AuthnRequest) XMLObjectSupport.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
          customizer.accept(ar);
          return requestObject;
        });
    final AuthenticationResultChoice result = handler.authenticate(authnReqs, null, this.context);

    Assertions.assertNull(result.getAuthenticationResult());
    Assertions.assertEquals("POST", result.getHttpRequestMessage().getMethod());
    Assertions.assertEquals(IDP_DESTINATION, result.getHttpRequestMessage().getUrl());
    Assertions.assertNotNull(result.getHttpRequestMessage().getHttpParameters().get("SAMLRequest"));

    Mockito.verify(this.context).put(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY),
        ArgumentMatchers.notNull());
    Mockito.verify(this.context).put(eq(SwedenConnectSamlAuthenticationHandler.SAD_ID_KEY),
        ArgumentMatchers.notNull());
    Mockito.verify(this.context).put(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY), eq("ID"));
    Mockito.verify(this.context).put(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY), eq(authnReqs));
  }

  @Test
  public void testResumeAuthenticationWithSignMessage() throws Exception {
    final SwedenConnectSamlAuthenticationHandler handler =
        (SwedenConnectSamlAuthenticationHandler) this.createHandler();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getServletPath()).thenReturn(ASSERTION_CONSUMER_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn("SAML-RESPONSE");
    Mockito.when(request.getParameter(eq("RelayState"))).thenReturn(CONTEXT_ID);

    final SignMessage signMessage = Mockito.mock(SignMessage.class);
    Mockito.when(signMessage.getMustShow()).thenReturn(true);
    Mockito.when(signMessage.getEncoding()).thenReturn(this.getEncodedSignMessage());

    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY), any()))
        .thenReturn(this.getEncodedAuthnRequest());
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY), any()))
        .thenReturn(CONTEXT_ID);
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY), any()))
        .thenReturn(signMessage);
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
                .build(),
            AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST)
                .friendlyName(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_SIGNMESSAGE_DIGEST)
                .value("dummy")
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

    final AuthenticationResultChoice result = handler.resumeAuthentication(request, this.context);

    Assertions.assertNull(result.getHttpRequestMessage());
    Assertions.assertNotNull(result.getAuthenticationResult());
    Assertions.assertTrue(result.getAuthenticationResult().signMessageDisplayed());
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
    Assertions.assertTrue(assertion.getIdentityAttributes().stream()
        .filter(a -> AttributeConstants.ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST.equals(a.getIdentifier()))
        .findFirst()
        .isPresent());

    // Assert that the context was cleaned
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY));
  }

  @Test
  public void testResumeAuthenticationWithSignMessageNotDisplayed() throws Exception {
    final SwedenConnectSamlAuthenticationHandler handler =
        (SwedenConnectSamlAuthenticationHandler) this.createHandler();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getServletPath()).thenReturn(ASSERTION_CONSUMER_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn("SAML-RESPONSE");
    Mockito.when(request.getParameter(eq("RelayState"))).thenReturn(CONTEXT_ID);

    final SignMessage signMessage = Mockito.mock(SignMessage.class);
    Mockito.when(signMessage.getMustShow()).thenReturn(true);
    Mockito.when(signMessage.getEncoding()).thenReturn(this.getEncodedSignMessage());

    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY), any()))
        .thenReturn(this.getEncodedAuthnRequest());
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY), any()))
        .thenReturn(CONTEXT_ID);
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY), any()))
        .thenReturn(signMessage);
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

    try {
      handler.resumeAuthentication(request, this.context);
      Assertions.fail("Expected UserAuthenticationException");
    }
    catch (final UserAuthenticationException e) {
      Assertions.assertEquals(AuthenticationErrorCode.FAILED_AUTHN, e.getErrorCode());
    }

    // Assert that the context was cleaned
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY));
  }

  @Test
  public void testResumeAuthenticationWithSignMessageButNotRequired() throws Exception {
    final SwedenConnectSamlAuthenticationHandler handler =
        (SwedenConnectSamlAuthenticationHandler) this.createHandler();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getServletPath()).thenReturn(ASSERTION_CONSUMER_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn("SAML-RESPONSE");
    Mockito.when(request.getParameter(eq("RelayState"))).thenReturn(CONTEXT_ID);

    final SignMessage signMessage = Mockito.mock(SignMessage.class);
    Mockito.when(signMessage.getMustShow()).thenReturn(false);
    Mockito.when(signMessage.getEncoding()).thenReturn(this.getEncodedSignMessage());

    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY), any()))
        .thenReturn(this.getEncodedAuthnRequest());
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY), any()))
        .thenReturn(CONTEXT_ID);
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY), any()))
        .thenReturn(signMessage);
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

    final AuthenticationResultChoice result = handler.resumeAuthentication(request, this.context);

    Assertions.assertNull(result.getHttpRequestMessage());
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
    Assertions.assertFalse(assertion.getIdentityAttributes().stream()
        .filter(a -> AttributeConstants.ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST.equals(a.getIdentifier()))
        .findFirst()
        .isPresent());

    // Assert that the context was cleaned
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY));
  }

  @Test
  public void testCreateAuthnRequestContext1() throws Exception {
    final SwedenConnectSamlAuthenticationHandler2 h =
        new SwedenConnectSamlAuthenticationHandler2(this.authnRequestGenerator, this.responseProcessor,
            this.metadataProvider, this.entityDescriptorContainer, this.spUrlConfiguration);

    final AuthnRequirements authnReqs = this.getAuthnRequirements();

    final SignMessage signMessage = Mockito.mock(SignMessage.class);
    Mockito.when(signMessage.getMustShow()).thenReturn(true);
    Mockito.when(signMessage.getEncoding()).thenReturn(this.getEncodedSignMessage());

    Mockito.when(this.idpMetadata.getEntityID()).thenReturn(IDP);
    final IDPSSODescriptor ssoDescriptor = Mockito.mock(IDPSSODescriptor.class);
    Mockito.when(ssoDescriptor.getExtensions()).thenReturn(this.getMetadataExtensions());
    Mockito.when(this.idpMetadata.getIDPSSODescriptor(any())).thenReturn(ssoDescriptor);

    final SwedishEidAuthnRequestGeneratorContext ac = (SwedishEidAuthnRequestGeneratorContext) h
        .createAuthnRequestContext(authnReqs, signMessage, this.context, this.idpMetadata);

    Assertions.assertNotNull(ac);

    final RequestedAuthnContext rac = ac.getRequestedAuthnContextBuilderFunction().apply(Arrays.asList(
        LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2,
        LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3), false);

    Assertions.assertTrue(rac.getAuthnContextClassRefs().stream()
        .map(AuthnContextClassRef::getURI)
        .filter(u -> u.equals(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3))
        .findFirst()
        .isPresent());
    Assertions.assertFalse(rac.getAuthnContextClassRefs().stream()
        .map(AuthnContextClassRef::getURI)
        .filter(u -> u.equals(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3_NONRESIDENT))
        .findFirst()
        .isPresent());
    Assertions.assertFalse(rac.getAuthnContextClassRefs().stream()
        .map(AuthnContextClassRef::getURI)
        .filter(u -> u.equals(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2))
        .findFirst()
        .isPresent());

    final PrincipalSelection ps = ac.getPrincipalSelectionBuilderFunction().get();
    Assertions.assertNotNull(ps);
    Assertions.assertTrue(ps.getMatchValues().size() == 1);
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
        ps.getMatchValues().get(0).getName());

    final se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessage sm =
        ac.getSignMessageBuilderFunction().apply(this.idpMetadata, null);
    Assertions.assertNotNull(sm);
    final byte[] encoding = DOMUtils.nodeToBytes(XMLObjectSupport.marshall(sm));
    Assertions.assertArrayEquals(signMessage.getEncoding(), encoding);
  }

  @Test
  public void testCreateAuthnRequestContext2() throws Exception {
    final SwedenConnectSamlAuthenticationHandler2 h =
        new SwedenConnectSamlAuthenticationHandler2(this.authnRequestGenerator, this.responseProcessor,
            this.metadataProvider, this.entityDescriptorContainer, this.spUrlConfiguration);

    final DefaultAuthnRequirements authnReqs = (DefaultAuthnRequirements) this.getAuthnRequirements();
    authnReqs.setAuthnContextIdentifiers(Collections.emptyList());
    authnReqs.setRequestedSignerAttributes(Arrays.asList(
        new StringSamlIdentityAttribute(AttributeConstants.ATTRIBUTE_NAME_PRID,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PRID, "NO:123456789"),
        new StringSamlIdentityAttribute(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME, Arrays.asList(GN1, GN2)),
        new StringSamlIdentityAttribute(AttributeConstants.ATTRIBUTE_NAME_SN,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_SN, SN)));

    Mockito.when(this.idpMetadata.getEntityID()).thenReturn(IDP);
    final IDPSSODescriptor ssoDescriptor = Mockito.mock(IDPSSODescriptor.class);
    Mockito.when(ssoDescriptor.getExtensions()).thenReturn(this.getMetadataExtensions());
    Mockito.when(this.idpMetadata.getIDPSSODescriptor(any())).thenReturn(ssoDescriptor);

    final SwedishEidAuthnRequestGeneratorContext ac = (SwedishEidAuthnRequestGeneratorContext) h
        .createAuthnRequestContext(authnReqs, null, this.context, this.idpMetadata);

    Assertions.assertNotNull(ac);

    final RequestedAuthnContext rac = ac.getRequestedAuthnContextBuilderFunction().apply(Arrays.asList(
        LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA2,
        LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3), false);
    Assertions.assertNull(rac);

    final PrincipalSelection ps = ac.getPrincipalSelectionBuilderFunction().get();
    Assertions.assertNull(ps);

    Assertions.assertNull(ac.getSignMessageBuilderFunction().apply(this.idpMetadata, null));
  }

  @Test
  public void testResumeAuthenticationWithSadVerify() throws Exception {
    final SwedenConnectSamlAuthenticationHandler handler =
        (SwedenConnectSamlAuthenticationHandler) this.createHandler();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getServletPath()).thenReturn(ASSERTION_CONSUMER_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn("SAML-RESPONSE");
    Mockito.when(request.getParameter(eq("RelayState"))).thenReturn(CONTEXT_ID);

    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY), any()))
        .thenReturn(this.getEncodedAuthnRequest());
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY), any()))
        .thenReturn(CONTEXT_ID);

    final AuthnRequirements authnReqs = this.getAuthnRequirements();
    ((DefaultAuthnRequirements) authnReqs).setSignatureActivationRequestData(
        new DefaultSignatureActivationRequestData(SIGNREQUEST_ID, 1, true));

    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY), any()))
        .thenReturn(authnReqs);
    Mockito.when(this.context.get(eq(SwedenConnectSamlAuthenticationHandler.SAD_ID_KEY), any())).thenReturn("UUID");

    final ResponseProcessingResult processingResult = Mockito.mock(ResponseProcessingResult.class);

    List<Attribute> attributes = List.of(
        AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_SAD)
        .friendlyName(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_SAD)
        .value("SADMOCK")
        .build(),
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
        .build(),
    AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST)
        .friendlyName(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_SIGNMESSAGE_DIGEST)
        .value("dummy")
        .build());

    Mockito.when(processingResult.getAttributes()).thenReturn(attributes);
    Mockito.when(processingResult.getAuthnContextClassUri()).thenReturn(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3);
    Mockito.when(processingResult.getAssertion()).thenReturn(this.getAssertion());
    Mockito.when(processingResult.getIssuer()).thenReturn(IDP);

    final Instant issuanceInstant = Instant.now().minusMillis(500L);
    Mockito.when(processingResult.getIssueInstant()).thenReturn(issuanceInstant);

    final Instant authnInstant = Instant.now().minusMillis(1000L);
    Mockito.when(processingResult.getAuthnInstant()).thenReturn(authnInstant);

    Mockito.when(this.responseProcessor.processSamlResponse(anyString(), anyString(), any(), any()))
        .thenReturn(processingResult);

    final SADValidator sadValidator = Mockito.mock(SADValidator.class);
    final SAD sad = Mockito.mock(SAD.class);
    Mockito.when(sadValidator.validate(any(), any())).thenReturn(sad);

    handler.setSadValidator(sadValidator);
    final AuthenticationResultChoice result = handler.resumeAuthentication(request, this.context);

    Assertions.assertNull(result.getHttpRequestMessage());
    Assertions.assertNotNull(result.getAuthenticationResult());
    Assertions.assertTrue(result.getAuthenticationResult().signMessageDisplayed());
    final IdentityAssertion assertion = result.getAuthenticationResult().getAssertion();
    Assertions.assertNotNull(assertion.getIdentifier());
    Assertions.assertEquals(IDP, assertion.getIssuer());
    Assertions.assertEquals(issuanceInstant, assertion.getIssuanceInstant());
    Assertions.assertNotNull(assertion.getEncodedAssertion());

    Assertions.assertTrue(assertion.getIdentityAttributes().stream()
        .filter(a -> AttributeConstants.ATTRIBUTE_NAME_SAD.equals(a.getIdentifier()))
        .findFirst()
        .isPresent());
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
    Assertions.assertTrue(assertion.getIdentityAttributes().stream()
        .filter(a -> AttributeConstants.ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST.equals(a.getIdentifier()))
        .findFirst()
        .isPresent());

    // Assert that the context was cleaned
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY));
    Mockito.verify(this.context).remove(eq(AbstractSamlAuthenticationHandler.SIGNMESSAGE_KEY));
  }

  @Test
  public void testResumeAuthenticationWithSadVerifyFailure() throws Exception {
    final SwedenConnectSamlAuthenticationHandler handler =
        (SwedenConnectSamlAuthenticationHandler) this.createHandler();

    final HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
    Mockito.when(request.getServletPath()).thenReturn(ASSERTION_CONSUMER_PATH);
    Mockito.when(request.getMethod()).thenReturn("POST");
    Mockito.when(request.getParameter(eq("SAMLResponse"))).thenReturn("SAML-RESPONSE");
    Mockito.when(request.getParameter(eq("RelayState"))).thenReturn(CONTEXT_ID);

    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHNREQUEST_KEY), any()))
        .thenReturn(this.getEncodedAuthnRequest());
    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.RELAY_STATE_KEY), any()))
        .thenReturn(CONTEXT_ID);

    final AuthnRequirements authnReqs = this.getAuthnRequirements();
    ((DefaultAuthnRequirements) authnReqs).setSignatureActivationRequestData(
        new DefaultSignatureActivationRequestData(SIGNREQUEST_ID, 1, true));

    Mockito.when(this.context.get(eq(AbstractSamlAuthenticationHandler.AUTHN_REQS_KEY), any()))
        .thenReturn(authnReqs);
    Mockito.when(this.context.get(eq(SwedenConnectSamlAuthenticationHandler.SAD_ID_KEY), any())).thenReturn("UUID");

    final ResponseProcessingResult processingResult = Mockito.mock(ResponseProcessingResult.class);

    List<Attribute> attributes = List.of(
        AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_SAD)
        .friendlyName(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_SAD)
        .value("SADMOCK")
        .build(),
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
        .build(),
    AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST)
        .friendlyName(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_SIGNMESSAGE_DIGEST)
        .value("dummy")
        .build());

    Mockito.when(processingResult.getAttributes()).thenReturn(attributes);
    Mockito.when(processingResult.getAuthnContextClassUri()).thenReturn(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3);
    Mockito.when(processingResult.getAssertion()).thenReturn(this.getAssertion());
    Mockito.when(processingResult.getIssuer()).thenReturn(IDP);

    final Instant issuanceInstant = Instant.now().minusMillis(500L);
    Mockito.when(processingResult.getIssueInstant()).thenReturn(issuanceInstant);

    final Instant authnInstant = Instant.now().minusMillis(1000L);
    Mockito.when(processingResult.getAuthnInstant()).thenReturn(authnInstant);

    Mockito.when(this.responseProcessor.processSamlResponse(anyString(), anyString(), any(), any()))
        .thenReturn(processingResult);

    final SADValidator sadValidator = Mockito.mock(SADValidator.class);
    final SADValidationException ex = new SADValidationException(ErrorCode.SIGNATURE_VALIDATION_ERROR, "Some text");
    Mockito.when(sadValidator.validate(any(), any())).thenThrow(ex);

    handler.setSadValidator(sadValidator);
    assertThatThrownBy(() -> {
      handler.resumeAuthentication(request, this.context);
    }).isInstanceOf(UserAuthenticationException.class)
      .hasMessageContaining("Verification of signature activation data (SAD) failed");
  }

  // We introduce this class to get hold of the results from createAuthnRequestContext.
  public static class SwedenConnectSamlAuthenticationHandler2 extends SwedenConnectSamlAuthenticationHandler {

    public SwedenConnectSamlAuthenticationHandler2(final AuthnRequestGenerator authnRequestGenerator,
        final ResponseProcessor responseProcessor, final MetadataProvider metadataProvider,
        final EntityDescriptorContainer entityDescriptorContainer, final SpUrlConfiguration urlConfiguration) {
      super(authnRequestGenerator, responseProcessor, metadataProvider, entityDescriptorContainer, urlConfiguration);
    }

    @Override
    public AuthnRequestGeneratorContext createAuthnRequestContext(final AuthnRequirements authnRequirements,
        final SignMessage signMessage, final SignServiceContext context, final EntityDescriptor idpMetadata)
        throws UserAuthenticationException {
      return super.createAuthnRequestContext(authnRequirements, signMessage, context, idpMetadata);
    }

  }

  protected byte[] getEncodedSignMessage() throws Exception {
    return DOMUtils.nodeToBytes(XMLObjectSupport.marshall(this.getSignMessage()));
  }

  protected se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessage getSignMessage() throws Exception {
    final Element elm =
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/signmessage.xml")).getDocumentElement();
    return (se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessage) XMLObjectSupport.getUnmarshaller(elm)
        .unmarshall(elm);
  }

  protected Extensions getMetadataExtensions() throws Exception {
    final Element elm =
        DOMUtils.inputStreamToDocument(this.getClass().getResourceAsStream("/idp-extensions.xml")).getDocumentElement();
    return (Extensions) XMLObjectSupport.getUnmarshaller(elm).unmarshall(elm);
  }

}
