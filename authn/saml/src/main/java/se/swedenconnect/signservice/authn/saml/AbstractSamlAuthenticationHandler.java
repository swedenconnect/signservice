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

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.w3c.dom.Element;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import se.idsec.signservice.xml.DOMUtils;
import se.idsec.signservice.xml.InternalXMLException;
import se.swedenconnect.opensaml.saml2.core.build.RequestedAuthnContextBuilder;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.saml2.metadata.provider.MetadataProvider;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.saml2.request.RequestGenerationException;
import se.swedenconnect.opensaml.saml2.request.RequestHttpObject;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingException;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingInput;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingResult;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessor;
import se.swedenconnect.opensaml.saml2.response.ResponseStatusErrorException;
import se.swedenconnect.signservice.authn.AuthenticationErrorCode;
import se.swedenconnect.signservice.authn.AuthenticationHandler;
import se.swedenconnect.signservice.authn.AuthenticationResult;
import se.swedenconnect.signservice.authn.AuthenticationResultChoice;
import se.swedenconnect.signservice.authn.AuthnContextIdentifier;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.authn.UserAuthenticationException;
import se.swedenconnect.signservice.authn.impl.DefaultIdentityAssertion;
import se.swedenconnect.signservice.authn.impl.SimpleAuthnContextIdentifier;
import se.swedenconnect.signservice.authn.saml.config.SpUrlConfiguration;
import se.swedenconnect.signservice.core.AbstractSignServiceHandler;
import se.swedenconnect.signservice.core.attribute.AttributeConverter;
import se.swedenconnect.signservice.core.attribute.AttributeException;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;
import se.swedenconnect.signservice.core.http.HttpResourceProvider;
import se.swedenconnect.signservice.protocol.msg.AuthnRequirements;
import se.swedenconnect.signservice.protocol.msg.SignMessage;
import se.swedenconnect.signservice.session.SignServiceContext;

/**
 * Abstract base class for SAML authentication handlers.
 */
@Slf4j
public abstract class AbstractSamlAuthenticationHandler extends AbstractSignServiceHandler
    implements AuthenticationHandler, HttpResourceProvider {

  /** Media type for SAML metadata in XML format. */
  public static final String APPLICATION_SAML_METADATA = "application/samlmetadata+xml";

  /** Prefix for all context values that we store/retrieve. */
  public static final String PREFIX = AbstractSamlAuthenticationHandler.class.getPackageName();

  /** Key for storing the AuthnRequest. */
  public static final String AUTHNREQUEST_KEY = PREFIX + ".AuthnRequest";

  /** Key for storing the RelayState. */
  public static final String RELAY_STATE_KEY = PREFIX + ".RelayState";

  /** Key for storing the authentication requirements. */
  public static final String AUTHN_REQS_KEY = PREFIX + ".AuthnRequirements";

  /** Key for storing the SignMessage. */
  public static final String SIGNMESSAGE_KEY = PREFIX + ".SignMessage";

  /** The bean used when creating authentication requests. */
  protected final AuthnRequestGenerator authnRequestGenerator;

  /** The bean used when processing SAML responses. */
  protected final ResponseProcessor responseProcessor;

  /** Holds the federation metadata. */
  protected final MetadataProvider metadataProvider;

  /** The container for this SP's SAML metadata. */
  protected final EntityDescriptorContainer entityDescriptorContainer;

  /** The URL configuration. */
  protected final SpUrlConfiguration urlConfiguration;

  /** The preferred SAML binding to use for authentication requests. */
  private String preferredBindingUri;

  /** For converting attributes between the generic representation and the OpenSAML representation. */
  protected static final AttributeConverter<Attribute> attributeConverter = new OpenSamlAttributeConverter();

  /**
   * Constructor.
   *
   * @param authnRequestGenerator the generator for creating authentication requests
   * @param responseProcessor the SAML response processor
   * @param metadataProvider the SAML metadata provider
   * @param entityDescriptorContainer the container for this SP's metadata
   * @param urlConfiguration the URL configuration
   */
  public AbstractSamlAuthenticationHandler(
      @Nonnull final AuthnRequestGenerator authnRequestGenerator,
      @Nonnull final ResponseProcessor responseProcessor,
      @Nonnull final MetadataProvider metadataProvider,
      @Nonnull final EntityDescriptorContainer entityDescriptorContainer,
      @Nonnull final SpUrlConfiguration urlConfiguration) {

    this.authnRequestGenerator =
        Objects.requireNonNull(authnRequestGenerator, "authnRequestGenerator must not be null");
    this.responseProcessor = Objects.requireNonNull(responseProcessor, "responseProcessor must not be null");
    this.metadataProvider = Objects.requireNonNull(metadataProvider, "metadataProvider must not be null");
    this.entityDescriptorContainer =
        Objects.requireNonNull(entityDescriptorContainer, "entityDescriptorContainer must not be null");
    this.urlConfiguration = Objects.requireNonNull(urlConfiguration, "urlConfiguration must not be null");
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public AuthenticationResultChoice authenticate(@Nonnull final AuthnRequirements authnRequirements,
      @Nullable final SignMessage signMessage, @Nonnull final SignServiceContext context)
      throws UserAuthenticationException {

    log.debug("{}: Authentication handler '{}' received request to authenticate user. [authn-requirements=[{}]]",
        context.getId(), this.getName(), authnRequirements);

    // Check SignMessage ...
    if (signMessage != null) {
      if (signMessage.getMustShow() && !this.isSignMessageSupported()) {
        final String msg = "Authentication requirements states that the SignMessage must be displayed "
            + "by the IdP, but the SignMessage concept is not supported in the current federation";
        log.info("{}: {}", context.getId(), msg);
        throw new UserAuthenticationException(AuthenticationErrorCode.FAILED_AUTHN, msg);
      }
    }

    // Get hold of the IdP metadata ...
    final EntityDescriptor idpMetadata = this.getIdpMetadata(authnRequirements, context);

    // Check if we need to send a SAD request ...
    if (authnRequirements.getSignatureActivationRequestData() != null) {
      if (authnRequirements.getSignatureActivationRequestData().isRequired()
          && signMessage != null
          && !this.isSignatureActivationProtocolSupported(idpMetadata)) {
        final String msg = "Authentication requirements states that a SAD request should be sent "
            + "but the IdP does not support the Signature Activation Data extension";
        log.info("{}: {}", context.getId(), msg);
        throw new UserAuthenticationException(AuthenticationErrorCode.FAILED_AUTHN, msg);
      }
    }

    // Create an authentication request context ...
    final AuthnRequestGeneratorContext authnContext =
        this.createAuthnRequestContext(authnRequirements, signMessage, context, idpMetadata);

    // Create authentication request ...
    try {
      final String relayState = context.getId();
      final RequestHttpObject<AuthnRequest> requestObject =
          this.authnRequestGenerator.generateAuthnRequest(idpMetadata.getEntityID(), relayState, authnContext);

      // Store the serialized authentication request message in the context along with
      // other data needed to verify the response (below) ...
      //
      this.storeAuthnRequest(requestObject.getRequest(), context);
      context.put(RELAY_STATE_KEY, relayState);
      context.put(AUTHN_REQS_KEY, authnRequirements);
      if (signMessage != null) {
        context.put(SIGNMESSAGE_KEY, signMessage);
      }

      // Build a return object (containing directions on how to redirect/POST the request).
      //
      final HttpRequestMessage message = new HttpRequestMessage() {

        @Override
        public String getUrl() {
          return requestObject.getSendUrl();
        }

        @Override
        public String getMethod() {
          return requestObject.getMethod();
        }

        @Override
        public Map<String, String> getHttpParameters() {
          return Optional.ofNullable(requestObject.getRequestParameters()).orElseGet(() -> Collections.emptyMap());
        }

        @Override
        public Map<String, String> getHttpHeaders() {
          return Optional.ofNullable(requestObject.getHttpHeaders()).orElseGet(() -> Collections.emptyMap());
        }
      };

      log.debug("{}: AuthnRequest generated - {}: {}", context.getId(), message.getMethod(), message.getUrl());
      return new AuthenticationResultChoice(message);
    }
    catch (final RequestGenerationException e) {
      final String msg = String.format("Failed to generate SAML authentication request - %s", e.getMessage());
      log.info("{}: {}", context.getId(), msg);
      throw new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR, msg, e);
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public AuthenticationResultChoice resumeAuthentication(@Nonnull final HttpServletRequest httpRequest,
      @Nonnull final SignServiceContext context) throws UserAuthenticationException {

    log.debug("{}: Authentication handler '{}' received request to resume authentication (process response)",
        context.getId(), this.getName());

    // Sanity check.
    if (!this.canProcess(httpRequest, null)) {
      throw new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR, "Received on unexpected URL");
    }

    try {
      // Get hold of the response parameters ...
      // The canProcess method has already asserted that the response parameter is there ...
      //
      final String samlResponse = httpRequest.getParameter("SAMLResponse");
      final String relayState = httpRequest.getParameter("RelayState");

      // Get hold of the saved authentication request (and relay state).
      //
      final AuthnRequest authnRequest = this.getAuthnRequest(context);
      if (authnRequest == null) {
        final String msg = "No AuthnRequest available is session - cannot process response";
        log.info("{}: {}", context.getId(), msg);
        throw new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR, msg);
      }
      final String sentRelayState = context.get(RELAY_STATE_KEY, String.class);

      // Setup the response processing input object ...
      //
      final ResponseProcessingInput input =
          this.createResponseProcessingInput(authnRequest, sentRelayState, httpRequest, context);

      // Next, process the response message ...
      //
      final ResponseProcessingResult processingResult = this.responseProcessor.processSamlResponse(
          samlResponse, relayState, input, this.createValidationContext(httpRequest, context));

      // Transform attributes to the generic representation ...
      final List<IdentityAttribute<?>> attributes = this.transformAttributes(processingResult.getAttributes());

      // Assert that we got all attributes that were required. With the correct values.
      //
      final AuthnRequirements authnRequirements =
          Optional.ofNullable(context.get(AUTHN_REQS_KEY, AuthnRequirements.class))
              .orElseThrow(() -> new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR,
                  "State error - missing information about authn requirements"));
      this.assertAttributes(authnRequirements, attributes, context);

      // Assert that the correct authentication context class was delivered in the assertion.
      //
      this.assertAuthnContext(authnRequest, processingResult.getAuthnContextClassUri(), context);

      // Assert SignMessage handling ...
      final SignMessage signMessage = context.get(SIGNMESSAGE_KEY, SignMessage.class);
      this.assertSignMessage(signMessage, attributes, processingResult, authnRequest, context);

      // Make additional checks concerning the assertion received ...
      //
      this.extendedAssertionVerification(authnRequirements, authnRequest, processingResult, context);

      // Build result ...
      //
      final IdentityAssertion identityAssertion = this.buildIdentityAssertion(processingResult, attributes, context);
      final boolean signMessageDisplayed =
          this.wasSignMessageDisplayed(processingResult, attributes, authnRequest, context);

      return new AuthenticationResultChoice(
          new AuthenticationResult() {

            private static final long serialVersionUID = 3481951951577173265L;

            @Override
            public boolean signMessageDisplayed() {
              return signMessageDisplayed;
            }

            @Override
            public IdentityAssertion getAssertion() {
              return identityAssertion;
            }
          });
    }
    catch (final ResponseStatusErrorException e) {
      final SamlStatus status = new SamlStatus(e.getStatus());

      log.info("{}: IdP responded with error response: {}", context.getId(), status);

      if (status.isCancel()) {
        throw new UserAuthenticationException(AuthenticationErrorCode.USER_CANCEL, "User cancelled authentication");
      }
      else if (StatusCode.NO_AUTHN_CONTEXT.equals(status.getMinorStatusCode())) {
        throw new UserAuthenticationException(AuthenticationErrorCode.UNSUPPORTED_AUTHNCONTEXT,
            status.getStatusMessage("Bad authentication context"), e);
      }
      else if (StatusCode.NO_SUPPORTED_IDP.equals(status.getMinorStatusCode())
          || StatusCode.NO_AVAILABLE_IDP.equals(status.getMinorStatusCode())) {
        // If we are communicating with a Proxy IdP.
        throw new UserAuthenticationException(AuthenticationErrorCode.UNKNOWN_AUTHENTICATION_SERVICE,
            status.getStatusMessage("Requested IdP is not available"), e);
      }
      else {
        throw new UserAuthenticationException(AuthenticationErrorCode.FAILED_AUTHN,
            String.format("Authentication failure: %s (%s)", status.getStatusMessage("Unknown authentication error"),
                status.getMinorStatusCode()),
            e);
      }
    }
    catch (final ResponseProcessingException e) {
      final String msg = String.format("Error processing SAML response - %s", e.getMessage());
      log.info("{}: {}", context.getId(), msg, e);
      throw new UserAuthenticationException(AuthenticationErrorCode.FAILED_AUTHN, msg, e);
    }
    finally {
      // Reset context ...
      this.resetContext(context);
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean canProcess(@Nonnull final HttpServletRequest httpRequest, @Nullable final SignServiceContext context) {
    // If the request is received on any of the registered assertion consumer service URLs
    // AND we are waiting for a response message we return true, otherwise false.
    //
    if (!"POST".equals(httpRequest.getMethod())) {
      log.debug("{}: Handler '{}' can not process response sent using {} method",
          Optional.ofNullable(context).map(SignServiceContext::getId).orElse(""), this.getName(),
          httpRequest.getMethod());
      return false;
    }
    if (httpRequest.getParameter("SAMLResponse") == null) {
      final String msg = "No SAMLResponse parameter in response";
      log.debug("{}: {}", Optional.ofNullable(context).map(SignServiceContext::getId).orElse(""), msg);
      return false;
    }

    final String requestPath = httpRequest.getServletPath();
    if (!(requestPath.equalsIgnoreCase(this.urlConfiguration.getAssertionConsumerPath())
        || (this.urlConfiguration.getAdditionalAssertionConsumerPath() != null
            && requestPath.equalsIgnoreCase(this.urlConfiguration.getAdditionalAssertionConsumerPath())))) {
      log.info("{}: Path {} is not supported by handler '{}'",
          Optional.ofNullable(context).map(SignServiceContext::getId).orElseGet(() -> ""), requestPath, this.getName());
      return false;
    }

    if (context != null && context.get(AUTHNREQUEST_KEY) == null) {
      log.debug("{}: No AuthnRequest available in session - can not process response message", context.getId());
      return false;
    }

    return true;
  }

  /** {@inheritDoc} */
  @Override
  public void getResource(
      @Nonnull final HttpServletRequest httpRequest, @Nonnull final HttpServletResponse httpResponse)
      throws IOException {

    log.debug("Request to download metadata from {}", httpRequest.getRemoteAddr());

    if (!this.supports(httpRequest)) {
      log.info("Invalid call to getResource on {}", this.getClass().getSimpleName());
      throw new IOException("Invalid call");
    }

    try {

      // Check if the metadata is up-to-date according to how the container was configured.
      //
      if (this.entityDescriptorContainer.updateRequired(true)) {
        log.debug("Metadata needs to be updated ...");
        this.entityDescriptorContainer.update(true);
        log.debug("Metadata was updated and signed");
      }
      else {
        log.debug("Metadata is up-to-date, using cached metadata");
      }

      // Assign the HTTP headers.
      //
      final String acceptHeader = httpRequest.getHeader("Accept");
      if (acceptHeader != null && acceptHeader.contains(APPLICATION_SAML_METADATA)) {
        httpResponse.setHeader("Content-Type", APPLICATION_SAML_METADATA);
      }
      else {
        httpResponse.setHeader("Content-Type", "application/xml");
      }

      // Get the DOM for the metadata, serialize it and write it to the response ...
      //
      final Element dom = this.entityDescriptorContainer.marshall();
      SerializeSupport.writeNode(dom, httpResponse.getOutputStream());
    }
    catch (final SignatureException | MarshallingException e) {
      log.error("Failed to return valid metadata", e);
      throw new IOException("Failed to produce SAML metadata", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean supports(@Nonnull final HttpServletRequest httpRequest) {
    if (!"GET".equals(httpRequest.getMethod())) {
      return false;
    }
    return httpRequest.getServletPath().equalsIgnoreCase(this.urlConfiguration.getMetadataPublishingPath());
  }

  /**
   * A predicate telling whether the concept of SignMessage is supported by the Identity Providers in the federation we
   * are using. The default implementation always returns {@code false}.
   *
   * @return whether the SignMessage-concept is supported by the handler
   */
  protected boolean isSignMessageSupported() {
    return false;
  }

  /**
   * A predicate telling whether the Signature Activation Protocol is supported by the given IdP. The default
   * implementation always returns {@code false}.
   * <p>
   * See <a href=
   * "https://docs.swedenconnect.se/technical-framework/latest/13_-_Signature_Activation_Protocol.html#sadrequest">Signature
   * Activation Protocol for Federated Signing</a>.
   * </p>
   *
   * @param idpMetadata the IdP metadata
   * @return whether the Signature Activation Protocol is supported
   */
  protected boolean isSignatureActivationProtocolSupported(@Nonnull final EntityDescriptor idpMetadata) {
    return false;
  }

  /**
   * Is invoked to reset the context, i.e., to remove elements that were added by this handler. If overridden, the super
   * implementation should always be called.
   *
   * @param context the SignService context.
   */
  protected void resetContext(@Nonnull final SignServiceContext context) {
    context.remove(AUTHNREQUEST_KEY);
    context.remove(RELAY_STATE_KEY);
    context.remove(AUTHN_REQS_KEY);
    context.remove(SIGNMESSAGE_KEY);
  }

  /**
   * Creates an {@link AuthnRequestGeneratorContext} object that is to be used by the configured
   * {@link AuthnRequestGenerator}.
   * <p>
   * The default implementation provides a
   * {@link AuthnRequestGeneratorContext#getRequestedAuthnContextBuilderFunction()} implementation that creates a
   * {@code RequestedAuthnContext} element containing the authentication context URI:s that are declared in the
   * {@link AuthnRequirements} <b>and</b> declared by the IdP in its metadata.
   * </p>
   *
   * @param authnRequirements the authentication requirements
   * @param signMessage the SignMessage
   * @param context the SignService context
   * @param idpMetadata the IdP metadata
   * @return a AuthnRequestGeneratorContext object
   * @throws UserAuthenticationException for errors creating the context
   */
  protected AuthnRequestGeneratorContext createAuthnRequestContext(
      @Nonnull final AuthnRequirements authnRequirements, @Nullable final SignMessage signMessage,
      @Nonnull final SignServiceContext context, @Nonnull final EntityDescriptor idpMetadata)
      throws UserAuthenticationException {

    // Processing regarding requested AuthnContext. If the IdP does not support what is requested,
    // we report an error ...
    //
    if (authnRequirements.getAuthnContextIdentifiers() != null
        && !authnRequirements.getAuthnContextIdentifiers().isEmpty()) {
      final List<String> supportedUris = EntityDescriptorUtils.getAssuranceCertificationUris(idpMetadata);
      final boolean match = authnRequirements.getAuthnContextIdentifiers().stream()
        .map(AuthnContextIdentifier::getIdentifier)
        .anyMatch(a -> supportedUris.contains(a));
      if (!match) {
        final String msg = "None of the requested authn context URIs are supported by the IdP";
        log.info("{}: {}", context.getId(), msg);
        throw new UserAuthenticationException(AuthenticationErrorCode.UNSUPPORTED_AUTHNCONTEXT, msg);
      }
    }

    return new AuthnRequestGeneratorContext() {

      @Override
      @Nonnull
      public String getPreferredBinding() {
        return getPreferredBindingUri();
      }

      @Override
      @Nullable
      public RequestedAuthnContextBuilderFunction getRequestedAuthnContextBuilderFunction() {
        return (list, hok) -> {
          if (authnRequirements.getAuthnContextIdentifiers() == null
              || authnRequirements.getAuthnContextIdentifiers().isEmpty()) {
            // If no authentication context classes have been declared in the requirements
            // we return null which means that no RequestedAuthnContext is created.
            //
            return null;
          }

          // Filter away the specified contexts that are not declared by the IdP.
          //
          final List<String> uris = authnRequirements.getAuthnContextIdentifiers().stream()
              .map(AuthnContextIdentifier::getIdentifier)
              .filter(i -> list.contains(i))
              .collect(Collectors.toList());

          if (uris.isEmpty()) {
            return null;
          }
          return RequestedAuthnContextBuilder.builder()
              .comparison(AuthnContextComparisonTypeEnumeration.EXACT)
              .authnContextClassRefs(uris)
              .build();
        };
      }

    };
  }

  /**
   * Creates a {@link ResponseProcessingInput} object based on the supplied parameters.
   *
   * @param authnRequest the AuthnRequest corresponding to the response
   * @param sentRelayState the RelayState that we sent along in the request (may be null)
   * @param httpRequest the HTTP servlet request
   * @param context the SignService context
   * @return a ResponseProcessingInput object
   */
  @Nonnull
  protected ResponseProcessingInput createResponseProcessingInput(
      @Nonnull AuthnRequest authnRequest, @Nullable String sentRelayState,
      @Nonnull final HttpServletRequest httpRequest, @Nonnull final SignServiceContext context) {

    final Instant received = Instant.now();
    final String baseUrl = this.urlConfiguration.getBaseUrl();

    return new ResponseProcessingInput() {

      @Override
      public AuthnRequest getAuthnRequest(final String id) {
        if (Objects.equals(id, authnRequest.getID())) {
          return authnRequest;
        }
        return null;
      }

      @Override
      public String getRequestRelayState(final String id) {
        return sentRelayState;
      }

      @Override
      public String getReceiveURL() {
        return baseUrl + httpRequest.getServletPath();
      }

      @Override
      public Instant getReceiveInstant() {
        return received;
      }

      @Override
      public String getClientIpAddress() {
        // We don't check IP addresses - it's too error prone.
        return null;
      }

      @Override
      public X509Certificate getClientCertificate() {
        // We don't support the Holder-of-key profile.
        return null;
      }
    };
  }

  /**
   * An OpenSAML {@link ValidationContext} may optionally be supplied to the response processing methods.
   * <p>
   * The default implementation returns {@code null}.
   * </p>
   *
   * @param httpRequest the HTTP servlet request
   * @param context the SignService context.
   * @return a ValidationContext or null
   */
  @Nullable
  protected ValidationContext createValidationContext(
      @Nonnull final HttpServletRequest httpRequest, @Nonnull final SignServiceContext context) {
    return null;
  }

  /**
   * Finds the Identity Provider metadata from the federation given the authentication requirements.
   *
   * @param authnRequirements the authentication requirements
   * @param context the SignService context
   * @return the IdP metadata entry
   * @throws UserAuthenticationException if the IdP is not found
   */
  @Nonnull
  protected EntityDescriptor getIdpMetadata(@Nonnull final AuthnRequirements authnRequirements,
      @Nonnull final SignServiceContext context) throws UserAuthenticationException {

    if (StringUtils.isBlank(authnRequirements.getAuthnServiceID())) {
      final String msg = "No Identity Provider entityID supplied in requirements";
      log.info("{}: {}", context.getId(), msg);
      throw new UserAuthenticationException(AuthenticationErrorCode.UNKNOWN_AUTHENTICATION_SERVICE, msg);
    }
    try {
      final EntityDescriptor idpMetadata = this.metadataProvider.getEntityDescriptor(
          authnRequirements.getAuthnServiceID(), IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
      if (idpMetadata == null) {
        final String msg = String.format("The Identity Provider '%s' was not found in the federation metadata",
            authnRequirements.getAuthnServiceID());
        log.info("{}: {}", context.getId(), msg);
        throw new UserAuthenticationException(AuthenticationErrorCode.UNKNOWN_AUTHENTICATION_SERVICE, msg);
      }
      return idpMetadata;
    }
    catch (final ResolverException e) {
      final String msg = String.format("Error while trying to locate metadata for IdP '%s'",
          authnRequirements.getAuthnServiceID());
      log.info("{}: {}", context.getId(), msg, e);
      throw new UserAuthenticationException(AuthenticationErrorCode.UNKNOWN_AUTHENTICATION_SERVICE, msg, e);
    }
  }

  /**
   * Transforms SAML attributes into the generic SignService-representation of attributes.
   *
   * @param attributes the SAML attributes to transform
   * @return a list of attributes in their generic representation
   * @throws UserAuthenticationException if an unsupported attribute is encountered
   */
  @Nonnull
  protected List<IdentityAttribute<?>> transformAttributes(@Nonnull final List<Attribute> attributes)
      throws UserAuthenticationException {
    final List<IdentityAttribute<?>> identityAttributes = new ArrayList<>();
    for (final Attribute a : attributes) {
      try {
        identityAttributes.add(attributeConverter.convert(a));
      }
      catch (final AttributeException e) {
        throw new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR,
            String.format("Failed to process attribute - %s", e.getMessage()), e);
      }
    }
    return identityAttributes;
  }

  /**
   * Asserts that all requested signer attributes (from the SignRequest) is provided among the attributes from the
   * identity assertion received from the IdP.
   *
   * @param authnRequirements the authentication requirements (including the requested attributes)
   * @param issuedAttributes the attributes from the assertion
   * @param context the SignService context
   * @throws UserAuthenticationException if requested attributes are not present in the issued attributes
   */
  protected void assertAttributes(@Nonnull final AuthnRequirements authnRequirements,
      @Nonnull final List<IdentityAttribute<?>> issuedAttributes, @Nonnull final SignServiceContext context)
      throws UserAuthenticationException {

    final List<IdentityAttribute<?>> requestedSignerAttributes = authnRequirements.getRequestedSignerAttributes();

    for (final IdentityAttribute<?> requestedAttribute : requestedSignerAttributes) {
      final IdentityAttribute<?> issuedAttribute = issuedAttributes.stream()
          .filter(a -> Objects.equals(a.getIdentifier(), requestedAttribute.getIdentifier()))
          .findFirst()
          .orElse(null);
      if (issuedAttribute == null) {
        final String msg = String.format("Attribute '%s' was required to be present, but is missing from assertion",
            requestedAttribute.getIdentifier());
        log.info("{}: {}", context.getId(), msg);
        throw new UserAuthenticationException(AuthenticationErrorCode.MISMATCHING_IDENTITY_ATTRIBUTES, msg);
      }
      // OK, the attribute is provided. Let's check its value.
      // Since we support multi-valued attributes, we have a match if at least one of the values
      // from the requested attribute is found in the issued attribute.
      //
      boolean match = false;
      for (final Object value : requestedAttribute.getValues()) {
        if (issuedAttribute.getValues().stream().filter(v -> Objects.equals(v, value)).findAny().isPresent()) {
          match = true;
          break;
        }
      }
      if (!match) {
        final String msg = String.format("Requirement for attribute '%s' was %s but assertion contains %s",
            requestedAttribute.getIdentifier(), requestedAttribute.getValues(), issuedAttribute.getValues());
        log.info("{}: {}", context.getId(), msg);
        throw new UserAuthenticationException(AuthenticationErrorCode.MISMATCHING_IDENTITY_ATTRIBUTES, msg);
      }
    }
    log.debug("{}: All requested signer attributes were found in assertion", context.getId());
  }

  /**
   * Asserts that we received an authentication context class that we can accept.
   *
   * @param authnRequest the authentication request
   * @param authnContextClassUri the authn context that we received in the assertion
   * @param context the SignService context
   * @throws UserAuthenticationException if we did not receive an acceptable context
   */
  protected void assertAuthnContext(@Nonnull final AuthnRequest authnRequest,
      @Nullable final String authnContextClassUri, @Nonnull final SignServiceContext context)
      throws UserAuthenticationException {

    // Get the authentication context:s that we sent in the request
    //
    if (authnRequest.getRequestedAuthnContext() == null) {
      return;
    }
    final List<String> requestedContexts = authnRequest.getRequestedAuthnContext().getAuthnContextClassRefs()
        .stream()
        .map(AuthnContextClassRef::getURI)
        .collect(Collectors.toList());

    if (requestedContexts.isEmpty()) {
      return;
    }
    if (authnContextClassUri == null) {
      final String msg = "No authn context class received in assertion";
      log.info("{}: {}", context.getId(), msg);
      throw new UserAuthenticationException(AuthenticationErrorCode.UNSUPPORTED_AUTHNCONTEXT, msg);
    }
    if (!requestedContexts.contains(authnContextClassUri)) {
      final String msg = String.format("The received authn context class '%s' was not among the requested %s",
          authnContextClassUri, requestedContexts);
      log.info("{}: {}", context.getId(), msg);
      throw new UserAuthenticationException(AuthenticationErrorCode.UNSUPPORTED_AUTHNCONTEXT, msg);
    }
  }

  /**
   * Asserts the signature message.
   * <p>
   * The default implementation does nothing.
   * </p>
   *
   * @param signMessage the sign message that was requsted (may be null)
   * @param attributes the received attributes
   * @param result the processing result
   * @param authnRequest the sent authentication request
   * @param context the SignService context
   * @throws UserAuthenticationException for errors asserting the sign message
   */
  protected void assertSignMessage(@Nullable final SignMessage signMessage,
      @Nonnull final List<IdentityAttribute<?>> attributes, @Nonnull final ResponseProcessingResult result,
      @Nonnull final AuthnRequest authnRequest, @Nonnull final SignServiceContext context)
      throws UserAuthenticationException {
    // NO-OP
  }

  /**
   * A method that enables sub-classes to extend the verification of the received assertion. The default implementation
   * does nothing.
   *
   * @param authnRequirements the authentication requirements
   * @param authnRequest the authentication request
   * @param result the result from the response processing (includes the assertion)
   * @param context the SignService context
   * @throws UserAuthenticationException for verification errors
   */
  protected void extendedAssertionVerification(@Nonnull final AuthnRequirements authnRequirements,
      @Nonnull final AuthnRequest authnRequest, @Nonnull ResponseProcessingResult result,
      @Nonnull final SignServiceContext context) throws UserAuthenticationException {
  }

  /**
   * Given a {@link ResponseProcessingResult} the method builds an {@link IdentityAssertion} object.
   *
   * @param result the result
   * @param context the SignService context
   * @param attributes the identity attributes
   * @return an IdentityAssertion
   * @throws UserAuthenticationException for errors during the transformation
   */
  @Nonnull
  protected IdentityAssertion buildIdentityAssertion(
      @Nonnull final ResponseProcessingResult result, @Nonnull final List<IdentityAttribute<?>> attributes,
      @Nonnull final SignServiceContext context) throws UserAuthenticationException {

    final DefaultIdentityAssertion assertion = new DefaultIdentityAssertion();
    final Assertion samlAssertion = result.getAssertion();

    assertion.setScheme("SAML");
    assertion.setIdentifier(samlAssertion.getID());
    assertion.setIssuer(result.getIssuer());
    assertion.setIssuanceInstant(result.getIssueInstant());
    assertion.setAuthnInstant(result.getAuthnInstant());
    assertion.setAuthnContext(new SimpleAuthnContextIdentifier(result.getAuthnContextClassUri()));
    try {
      assertion.setEncodedAssertion(DOMUtils.nodeToBytes(XMLObjectSupport.marshall(samlAssertion)));
    }
    catch (final MarshallingException | InternalXMLException e) {
      final String msg = "Failed to unmarshall Assertion";
      log.info("{}: {} - {}", context.getId(), msg, e.getMessage());
      throw new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR, msg, e);
    }
    assertion.setIdentityAttributes(attributes);
    return assertion;
  }

  /**
   * Given the {@link ResponseProcessingResult} and the {@code AuthnRequest} the method determines if the sign message
   * was displayed. The default implementation of this method always returns {@code false}.
   *
   * @param result the processing result
   * @param attributes the received attributes (in generic format)
   * @param authnRequest the authentication request
   * @param context the SignService context
   * @return a flag indicating whether the sign message was displayed or not
   * @throws UserAuthenticationException for processing errors, i.e., the proof for a displayed sign message is illegal
   */
  protected boolean wasSignMessageDisplayed(@Nonnull final ResponseProcessingResult result,
      @Nonnull List<IdentityAttribute<?>> attributes, @Nonnull final AuthnRequest authnRequest,
      @Nonnull final SignServiceContext context) throws UserAuthenticationException {
    return false;
  }

  /**
   * Stores a generated {@code AuthnRequest} message in the SignService context.
   *
   * @param authnRequest the object to store
   * @param context the context that we are storing the object in
   * @throws UserAuthenticationException for storage errors
   */
  protected void storeAuthnRequest(@Nonnull final AuthnRequest authnRequest, @Nonnull final SignServiceContext context)
      throws UserAuthenticationException {
    try {
      // Before storing the AuthnRequest in the context we need to make sure it is serializable.
      // We do that by marshalling it to a DOM object and to get the bytes ...
      context.put(AUTHNREQUEST_KEY, DOMUtils.nodeToBytes(XMLObjectSupport.marshall(authnRequest)));
    }
    catch (final MarshallingException | InternalXMLException e) {
      final String msg = "Failed to marshall AuthnRequest object";
      log.info("{}: {} - {}", context.getId(), msg, e.getMessage());
      throw new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR, msg, e);
    }
  }

  /**
   * Gets the stored {@code AuthnRequest} from the session context.
   *
   * @param context the context
   * @return an AuthnRequest object or null if no message is stored
   * @throws UserAuthenticationException for unmarshalling errors
   */
  @Nullable
  protected AuthnRequest getAuthnRequest(@Nonnull final SignServiceContext context) throws UserAuthenticationException {
    final byte[] encodedAuthnRequest = context.get(AUTHNREQUEST_KEY, byte[].class);
    if (encodedAuthnRequest == null) {
      log.debug("{}: No AuthnRequest available in session", context.getId());
      return null;
    }
    try {
      final Element xml = DOMUtils.bytesToDocument(encodedAuthnRequest).getDocumentElement();
      final Unmarshaller unmarshaller = Optional.ofNullable(XMLObjectSupport.getUnmarshaller(xml))
          .orElseThrow(() -> new UnmarshallingException("No unmarshaller for AuthnRequest available"));
      return AuthnRequest.class.cast(unmarshaller.unmarshall(xml));
    }
    catch (final UnmarshallingException | InternalXMLException e) {
      final String msg = "Failed to unmarshall AuthnRequest object";
      log.info("{}: {} - {}", context.getId(), msg, e.getMessage());
      throw new UserAuthenticationException(AuthenticationErrorCode.INTERNAL_AUTHN_ERROR, msg, e);
    }
  }

  /**
   * Gets the preferred SAML binding to use for authentication requests.
   *
   * @return the binding URI
   */
  @Nonnull
  protected String getPreferredBindingUri() {
    return Optional.ofNullable(this.preferredBindingUri).orElseGet(() -> SAMLConstants.SAML2_REDIRECT_BINDING_URI);
  }

  /**
   * Assigns the preferred SAML binding to use for authentication requests.
   *
   * @param preferredBindingUri the binding URI
   */
  public void setPreferredBindingUri(@Nonnull final String preferredBindingUri) {
    this.preferredBindingUri = preferredBindingUri;
  }

}
