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

import java.io.IOException;
import java.security.KeyException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.signservice.audit.AuditEventIds;
import se.swedenconnect.signservice.audit.AuditLogger;
import se.swedenconnect.signservice.audit.AuditLoggerSingleton;
import se.swedenconnect.signservice.authn.AuthenticationErrorCode;
import se.swedenconnect.signservice.authn.AuthenticationResult;
import se.swedenconnect.signservice.authn.AuthenticationResultChoice;
import se.swedenconnect.signservice.authn.UserAuthenticationException;
import se.swedenconnect.signservice.core.attribute.IdentityAttribute;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;
import se.swedenconnect.signservice.core.http.HttpResourceProvider;
import se.swedenconnect.signservice.core.types.InvalidRequestException;
import se.swedenconnect.signservice.engine.config.EngineConfiguration;
import se.swedenconnect.signservice.engine.session.EngineContext;
import se.swedenconnect.signservice.engine.session.SignOperationState;
import se.swedenconnect.signservice.protocol.ProtocolException;
import se.swedenconnect.signservice.protocol.ProtocolHandler;
import se.swedenconnect.signservice.protocol.ProtocolProcessingRequirements.SignatureRequirement;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.SignResponseMessage;
import se.swedenconnect.signservice.protocol.SignResponseResult;
import se.swedenconnect.signservice.protocol.msg.AuthnRequirements;
import se.swedenconnect.signservice.protocol.msg.CertificateAttributeMapping;
import se.swedenconnect.signservice.protocol.msg.SignMessage;
import se.swedenconnect.signservice.protocol.msg.SigningCertificateRequirements;
import se.swedenconnect.signservice.protocol.msg.impl.DefaultSignerAuthnInfo;
import se.swedenconnect.signservice.session.SessionHandler;
import se.swedenconnect.signservice.session.SignServiceContext;
import se.swedenconnect.signservice.session.SignServiceSession;
import se.swedenconnect.signservice.signature.CompletedSignatureTask;
import se.swedenconnect.signservice.signature.RequestedSignatureTask;
import se.swedenconnect.signservice.signature.SignatureHandler;
import se.swedenconnect.signservice.storage.MessageReplayChecker;
import se.swedenconnect.signservice.storage.MessageReplayException;

/**
 * The default implementation of the {@link SignServiceEngine} API.
 */
@Slf4j
public class DefaultSignServiceEngine implements SignServiceEngine {

  /** The engine's configuration. */
  private final EngineConfiguration engineConfiguration;

  /** The session handler. */
  private final SessionHandler sessionHandler;

  /** The message replay checker. */
  private final MessageReplayChecker messageReplayChecker;

  /** The sign message verifier. */
  private SignRequestMessageVerifier signRequestMessageVerifier;

  /** The system audit logger. */
  private AuditLogger systemAuditLogger;

  /**
   * Constructor.
   *
   * @param engineConfiguration the engine configuration
   * @param sessionHandler the session handler to use
   * @param messageReplayChecker the message replay checker
   * @param systemAuditLogger the system audit logger
   */
  public DefaultSignServiceEngine(
      final EngineConfiguration engineConfiguration,
      final SessionHandler sessionHandler,
      final MessageReplayChecker messageReplayChecker,
      final AuditLogger systemAuditLogger) {
    this.engineConfiguration = Objects.requireNonNull(engineConfiguration, "engineConfiguration must not be null");
    this.sessionHandler = Objects.requireNonNull(sessionHandler, "sessionHandler must not be null");
    this.messageReplayChecker = Objects.requireNonNull(messageReplayChecker, "messageReplayChecker must not be null");
    this.systemAuditLogger = Objects.requireNonNull(systemAuditLogger, "systemAuditLogger must not be null");
  }

  /** {@inheritDoc} */
  @PostConstruct
  @Override
  public void init() throws Exception {
    if (this.signRequestMessageVerifier == null) {
      log.debug("{}: Setting default signRequestMessageVerifier to {}",
          this.getName(), DefaultSignRequestMessageVerifier.class.getSimpleName());
      this.signRequestMessageVerifier = new DefaultSignRequestMessageVerifier();
    }
    this.systemAuditLogger.auditLog(AuditEventIds.EVENT_ENGINE_STARTED, (b) -> b
        .parameter("engine-name", this.getName())
        .parameter("client-id", this.engineConfiguration.getClientConfiguration().getClientId())
        .build());
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getName() {
    return this.engineConfiguration.getName();
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public HttpRequestMessage processRequest(
      @Nonnull final HttpServletRequest httpRequest, @Nonnull final HttpServletResponse httpResponse)
      throws UnrecoverableSignServiceException {

    log.debug("{}: Received request [path: '{}', client-ip: '{}']",
        this.getName(), httpRequest.getRequestURI(), httpRequest.getRemoteAddr());

    // Assign the audit logger to TLS so that any underlying component can get hold of the logger.
    //
    AuditLoggerSingleton.init(this.engineConfiguration.getAuditLogger());

    // Before processing the request, check if it is a request for an HTTP resource ...
    //
    final HttpResourceProvider resourceProvider = this.engineConfiguration.getHttpResourceProviders().stream()
        .filter(p -> p.supports(httpRequest))
        .findFirst()
        .orElse(null);
    if (resourceProvider != null) {
      try {
        log.debug("{}: Getting resource ... [path: '{}']",
            this.getName(), httpRequest.getRequestURI());
        resourceProvider.getResource(httpRequest, httpResponse);
        return null;
      }
      catch (final IOException e) {
        log.info("{}: Error getting HTTP resource '{}' - {}",
            this.getName(), httpRequest.getRequestURI(), e.getMessage(), e);
        throw new UnrecoverableSignServiceException(
            UnrecoverableErrorCodes.HTTP_GET_ERROR, "Failed to get resource", e);
      }
    }

    // Based on the context state and the URL on which we received the request do dispatching ...
    //
    EngineContext context = null;
    try {
      context = this.getContext(httpRequest);

      if (this.isSignRequestEndpoint(httpRequest)) {
        if (context.getState() == SignOperationState.NEW) {
          // Initiate new operation ...
          return this.processSignRequest(httpRequest, context);
        }
        else if (context.getState() == SignOperationState.AUTHN_ONGOING) {
          // OK, it seems that we have received a SignRequest in a session that is not
          // completed. This means that we abandon the previous context and start a new
          // one. We can only serve one request per session, and it is more likely that
          // a new SignRequest means that the user has terminated the previous operation
          // before it is complete.
          //
          log.info("{}: Abandoning ongoing operation - "
              + "A new SignRequest has been received in the same session [id: '{}']",
              this.getName(), context.getId());

          final String previousSignRequestId = Optional.ofNullable(context.getSignRequest())
              .map(SignRequestMessage::getRequestId)
              .orElseGet(() -> "-");

          context = this.resetContext(httpRequest);
          log.info("{}: New context has been created [id: '{}']", this.getName(), context.getId());

          this.engineConfiguration.getAuditLogger().auditLog(AuditEventIds.EVENT_ENGINE_SESSION_RESET, (b) -> b
              .parameter("engine-name", this.getName())
              .parameter("client-id", this.engineConfiguration.getClientConfiguration().getClientId())
              .parameter("abandoned-request-id", previousSignRequestId)
              .build());

          return this.processSignRequest(httpRequest, context);
        }
        // else: We are in state "SIGNING", and this is really odd. It must mean that the
        // user after he/she has authenticated has opened a new web browser tab and initiated
        // a new signature operation during the time the engine is performing the signature operation.
        // In these cases we refuse to accept the new invocation and let the original operation finish.
      }
      else if (context.getState() == SignOperationState.AUTHN_ONGOING) {
        try {
          return this.resumeAuthentication(httpRequest, context);
        }
        catch (final SignServiceErrorException e) {
          return this.sendErrorResponse(httpRequest, context, e.getError());
        }
      }
      log.info("{}: State error - Engine is is '{}' state. Can not process request '{}' [id: '{}']",
          this.getName(), context.getState(), httpRequest.getRequestURI(), context.getId());

      throw new UnrecoverableSignServiceException(UnrecoverableErrorCodes.STATE_ERROR,
          "State error - did not expect message");
    }
    catch (final UnrecoverableSignServiceException | RuntimeException e) {

      // Audit log
      //
      final EngineContext ctx = context != null ? context : null;
      this.engineConfiguration.getAuditLogger().auditLog(AuditEventIds.EVENT_ENGINE_SIGNATURE_OPERATION_FAILURE,
          (b) -> b
              .parameter("engine-name", this.getName())
              .parameter("client-id", this.engineConfiguration.getClientConfiguration().getClientId())
              .parameter("request-id",
                  Optional.ofNullable(ctx).map(EngineContext::getSignRequest).map(SignRequestMessage::getRequestId)
                      .orElseGet(() -> "-"))
              .parameter("error-code", UnrecoverableSignServiceException.class.isInstance(e)
                  ? UnrecoverableSignServiceException.class.cast(e).getErrorCode()
                  : "runtime-exception")
              .parameter("error-message", e.getMessage())
              .build());

      this.removeContext(httpRequest);
      throw e;
    }
  }

  /**
   * Initializes the processing of a sign request message.
   *
   * @param httpRequest the HTTP servlet request
   * @param context the engine context
   * @return a HttpRequestMessage
   * @throws UnrecoverableSignServiceException for unrecoverable errors
   */
  protected HttpRequestMessage processSignRequest(
      final HttpServletRequest httpRequest, final EngineContext context) throws UnrecoverableSignServiceException {

    try {
      // Decode the incoming request ...
      //
      final SignRequestMessage signRequestMessage = this.decodeMessage(httpRequest, context);

      // Make sure that this is not a replay attack ...
      //
      try {
        this.messageReplayChecker.checkReplay(signRequestMessage.getRequestId());
      }
      catch (final MessageReplayException e) {
        log.warn("{}: Replay attack detected for message '{}' [id: '{}']",
            this.getName(), signRequestMessage.getRequestId(), context.getId());

        throw new UnrecoverableSignServiceException(
            UnrecoverableErrorCodes.REPLAY_ATTACK, "Message is already being processed");
      }

      // Verify sign request message ...
      //
      this.signRequestMessageVerifier.verifyMessage(signRequestMessage, this.engineConfiguration, context);

      // Ask handlers if they will be able to process this request.
      //
      try {
        this.engineConfiguration.getKeyAndCertificateHandler().checkRequirements(
            signRequestMessage, context.getContext());
        this.engineConfiguration.getSignatureHandler().checkRequirements(signRequestMessage, context.getContext());
      }
      catch (final InvalidRequestException e) {
        log.info("{}: Cannot process request - {} [id: '{}', request-id: '{}']",
            this.getName(), e.getMessage(), context.getId(), signRequestMessage.getRequestId());
        throw new SignServiceErrorException(
            new SignServiceError(SignServiceErrorCode.REQUEST_INCORRECT, "Can not process request", e.getMessage()), e);
      }

      // OK, the SignRequest is accepted. Let's save it in the context for future use ...
      //
      context.putSignRequest(signRequestMessage);

      // Init authentication ...
      //
      final AuthenticationResultChoice authnResult = this.initAuthentication(httpRequest, signRequestMessage, context);
      if (authnResult.getHttpRequestMessage() != null) {
        log.debug(
            "{}: Authentication handler '{}' re-directing user for authentication ... [id: '{}', request-id: '{}']",
            this.getName(), this.engineConfiguration.getAuthenticationHandler().getName(),
            context.getId(), signRequestMessage.getRequestId());

        // Update the state ...
        //
        context.updateState(SignOperationState.AUTHN_ONGOING);

        return authnResult.getHttpRequestMessage();
      }
      else {
        log.debug("{}: Authentication handler '{}' successfully authenticated user, "
            + "proceeding with additional checks ... [id: '{}', request-id: '{}']",
            this.getName(), this.engineConfiguration.getAuthenticationHandler().getName(),
            context.getId(), signRequestMessage.getRequestId());

        return this.finalizeSignRequest(httpRequest, authnResult.getAuthenticationResult(), context);
      }
    }
    catch (final SignServiceErrorException e) {
      return this.sendErrorResponse(httpRequest, context, e.getError());
    }
  }

  /**
   * The finalize step is invoked after the user authentication is finished and the method proceeds to complete the
   * signature operation.
   *
   * @param httpRequest the HTTP request
   * @param authnResult the authentication result
   * @param context the engine context
   * @return a HttpRequestMessage
   * @throws UnrecoverableSignServiceException for unrecoverable errors
   */
  protected HttpRequestMessage finalizeSignRequest(
      final HttpServletRequest httpRequest, final AuthenticationResult authnResult, final EngineContext context)
      throws UnrecoverableSignServiceException {

    PkiCredential signingCredential = null;
    try {
      context.updateState(SignOperationState.SIGNING);

      // OK, we are called after the user has completed the authentication. However, we still have to
      // check that the authentication step gave us the information we need to continue the signature
      // operation. This is done in the "complete authentication" phase.
      //
      this.completeAuthentication(httpRequest, authnResult, context);

      // Generate the signing credentials (private key and certificate) ...
      //
      final SignRequestMessage signRequestMessage = context.getSignRequest();

      signingCredential = this.engineConfiguration.getKeyAndCertificateHandler().generateSigningCredential(
          signRequestMessage, authnResult.getAssertion(), context.getContext());

      // Sign the requested tasks ...
      //
      final List<CompletedSignatureTask> tasks = new ArrayList<>();
      final SignatureHandler signatureHandler = this.engineConfiguration.getSignatureHandler();
      for (final RequestedSignatureTask task : signRequestMessage.getSignatureTasks()) {
        tasks.add(signatureHandler.sign(task, signingCredential, signRequestMessage, context.getContext()));
      }

      // Create, sign and encode the sign response message ...
      //
      final ProtocolHandler protocolHandler = this.engineConfiguration.getProtocolHandler();
      final SignResponseMessage signResponseMessage =
          protocolHandler.createSignResponseMessage(context.getContext(), signRequestMessage);

      signResponseMessage.setSignResponseResult(protocolHandler.createSuccessResult());
      signResponseMessage.setRelayState(signRequestMessage.getRelayState());

      signResponseMessage.setInResponseTo(signRequestMessage.getRequestId());
      signResponseMessage.setIssuerId(this.engineConfiguration.getSignServiceId());

      if (StringUtils.isNotBlank(signRequestMessage.getResponseUrl())) {
        // The URL should have been checked against client configuration (if active) ...
        signResponseMessage.setDestinationUrl(signRequestMessage.getResponseUrl());
      }
      else {
        final String url = Optional.ofNullable(this.engineConfiguration.getClientConfiguration().getResponseUrls())
            .filter(urls -> !urls.isEmpty())
            .map(urls -> urls.get(0))
            .orElseThrow(
                () -> new ProtocolException("No response URL given in request and no URL configured for client"));
        signResponseMessage.setDestinationUrl(url);
      }

      signResponseMessage.setIssuedAt(Instant.now());
      signResponseMessage.setSignatureCertificateChain(signingCredential.getCertificateChain());
      signResponseMessage.setSignatureTasks(tasks);

      // TODO: We should strip of some of the authentication attributes from the assertion (if not asked for).
      signResponseMessage.setSignerAuthnInfo(new DefaultSignerAuthnInfo(authnResult.getAssertion()));

      // Sign
      if (signResponseMessage.getProcessingRequirements()
          .getResponseSignatureRequirement() == SignatureRequirement.REQUIRED) {
        signResponseMessage.sign(this.engineConfiguration.getSignServiceCredential());
      }

      // Get the result ...
      final HttpRequestMessage result = protocolHandler.encodeResponse(signResponseMessage, context.getContext());

      // Audit log
      //
      this.engineConfiguration.getAuditLogger().auditLog(AuditEventIds.EVENT_ENGINE_SIGNATURE_OPERATION_SUCCESS,
          (b) -> b
              .parameter("engine-name", this.getName())
              .parameter("client-id", this.engineConfiguration.getClientConfiguration().getClientId())
              .parameter("request-id",
                  Optional.ofNullable(context).map(EngineContext::getSignRequest).map(SignRequestMessage::getRequestId)
                      .orElseGet(() -> "-"))
              .build());

      // Clean up the context
      this.removeContext(httpRequest);

      return result;
    }
    catch (final SignatureException e) {
      log.info("{}: Failed to sign response message - {}. [id: '{}']",
          this.getName(), e.getMessage(), context.getId(), e);
      throw new UnrecoverableSignServiceException(
          UnrecoverableErrorCodes.INTERNAL_ERROR, "Failed to sign response message", e);
    }
    catch (final KeyException e) {
      log.info("{}: Failed to generate signing key - {}. [id: '{}']",
          this.getName(), e.getMessage(), context.getId(), e);
      return this.sendErrorResponse(httpRequest, context,
          new SignServiceError(SignServiceErrorCode.KEY_GENERATION_FAILED));
    }
    catch (final CertificateException e) {
      log.info("{}: Failed to generate signing certificate - {}. [id: '{}']",
          this.getName(), e.getMessage(), context.getId(), e);
      return this.sendErrorResponse(httpRequest, context,
          new SignServiceError(SignServiceErrorCode.CERT_ISSUANCE_FAILED));
    }
    catch (final ProtocolException e) {
      log.info("{}: Failed to produce response message - {}. [id: '{}']",
          this.getName(), e.getMessage(), context.getId(), e);
      throw new UnrecoverableSignServiceException(
          UnrecoverableErrorCodes.PROTOCOL_ERROR, "Failed to produce response message", e);
    }
    catch (final SignServiceErrorException e) {
      return this.sendErrorResponse(httpRequest, context, e.getError());
    }
    finally {
      if (signingCredential != null) {
        try {
          signingCredential.destroy();
        }
        catch (final Exception e) {
          log.warn("{}: Error during destruction of user signing credential - {} [id: '{}']",
              this.getName(), e.getMessage(), context.getId(), e);
        }
      }
    }
  }

  /**
   * Decodes a sign request message.
   *
   * @param httpRequest the HTTP servlet request
   * @param context the engine context
   * @return a generic representation of the sign request message
   * @throws UnrecoverableSignServiceException for unrecoverable errors
   */
  protected SignRequestMessage decodeMessage(
      final HttpServletRequest httpRequest, final EngineContext context) throws UnrecoverableSignServiceException {
    try {
      log.debug("{}: Decoding sign request message ... [id: '{}']",
          this.getName(), context.getId());

      final SignRequestMessage requestMessage = this.engineConfiguration.getProtocolHandler()
          .decodeRequest(httpRequest, context.getContext());

      log.debug("{}: Successfully decoded incoming sign request message. [id: '{}', request-id: '{}']",
          this.getName(), context.getId(), requestMessage.getRequestId());
      if (log.isTraceEnabled()) {
        log.trace("{}: [id: '{}'] {}",
            this.getName(), context.getId(), requestMessage);
      }

      return requestMessage;
    }
    catch (final ProtocolException e) {
      log.info("{}: Failed to decode incoming sign request - {}. [id: '{}']",
          this.getName(), e.getMessage(), context.getId(), e);
      throw new UnrecoverableSignServiceException(
          UnrecoverableErrorCodes.PROTOCOL_ERROR, "Failed to decode sign request", e);
    }
  }

  /**
   * Initializes the user authentication phase.
   *
   * @param httpRequest the HTTP request
   * @param signRequest the SignRequest message
   * @param context the context
   * @return an AuthenticationResultChoice
   * @throws SignServiceErrorException for errors (will lead to an error response)
   */
  protected AuthenticationResultChoice initAuthentication(
      final HttpServletRequest httpRequest, final SignRequestMessage signRequest, final EngineContext context)
      throws SignServiceErrorException {

    log.debug("{}: Initializing authentication ... [id: '{}', request-id: '{}']",
        this.getName(), context.getId(), signRequest.getRequestId());

    try {
      // TODO: The authentication requirements may also be controlled by a policy ...
      // TODO: We need to extend the input to authenticate with a listing of all attributes
      // required. We get those from the signing certificate requirements ...
      final AuthnRequirements reqs = signRequest.getAuthnRequirements();

      return this.engineConfiguration.getAuthenticationHandler().authenticate(
          reqs, signRequest.getSignMessage(), context.getContext());
    }
    catch (final UserAuthenticationException e) {
      log.info("{}: Authentication error: {} - {} [id: '{}', request-id: '{}']", this.getName(),
          e.getErrorCode(), e.getMessage(), context.getId(), signRequest.getRequestId());

      this.engineConfiguration.getAuditLogger().auditLog(AuditEventIds.EVENT_ENGINE_USER_AUTHN_FAILED, (b) -> b
          .parameter("engine-name", this.getName())
          .parameter("client-id", this.engineConfiguration.getClientConfiguration().getClientId())
          .parameter("request-id", signRequest.getRequestId())
          .parameter("error-code", e.getErrorCode().name())
          .parameter("error-message", e.getMessage())
          .build());

      throw this.mapAuthenticationError(e);
    }
  }

  /**
   * Is called when the engine is invoked after the user has been directed to the authentication service. When the
   * authentication is resumed it means that the issued authentication credentials (assertion) is being processed by the
   * authentication handler. If everything is ok, the control is the passed back to the "finalize" phase.
   *
   * @param httpRequest the HTTP request
   * @param context the engine context
   * @return a HttpRequestMessage object
   * @throws UnrecoverableSignServiceException for unrecoverable errors
   * @throws SignServiceErrorException for errors that should be passed back to the client (as an error response)
   */
  protected HttpRequestMessage resumeAuthentication(
      final HttpServletRequest httpRequest, final EngineContext context)
      throws UnrecoverableSignServiceException, SignServiceErrorException {

    // Assert that the request was received on a correct endpoint ...
    //
    if (!this.engineConfiguration.getAuthenticationHandler().canProcess(httpRequest, context.getContext())) {
      log.info("{}: Unexpected path '{}' [id: '{}']",
          this.getName(), httpRequest.getRequestURI(), context.getId());

      throw new UnrecoverableSignServiceException(
          UnrecoverableErrorCodes.NOT_FOUND, "Not found - " + httpRequest.getRequestURI());
    }

    try {
      final AuthenticationResultChoice authnChoice = this.engineConfiguration.getAuthenticationHandler()
          .resumeAuthentication(httpRequest, context.getContext());

      if (authnChoice.getHttpRequestMessage() != null) {
        // OK, it seems like the authentication scheme redirects the user time to an external service (again).
        return authnChoice.getHttpRequestMessage();
      }
      else {
        // Authentication is complete - proceed ...
        return this.finalizeSignRequest(httpRequest, authnChoice.getAuthenticationResult(), context);
      }
    }
    catch (final UserAuthenticationException e) {
      log.info("{}: Authentication error: {} - {} [id: '{}', request-id: '{}']", this.getName(),
          e.getErrorCode(), e.getMessage(), context.getId(), context.getSignRequest().getRequestId());

      this.engineConfiguration.getAuditLogger().auditLog(AuditEventIds.EVENT_ENGINE_USER_AUTHN_FAILED, (b) -> b
          .parameter("engine-name", this.getName())
          .parameter("client-id", this.engineConfiguration.getClientConfiguration().getClientId())
          .parameter("request-id",
              Optional.ofNullable(context.getSignRequest()).map(SignRequestMessage::getRequestId).orElseGet(() -> "-"))
          .parameter("error-code", e.getErrorCode().name())
          .parameter("error-message", e.getMessage())
          .build());

      throw this.mapAuthenticationError(e);
    }
  }

  /**
   * Maps an {@link UserAuthenticationException} to a {@link SignServiceErrorException} which controls how an error
   * response is sent back to the client.
   *
   * @param e the expception to map
   * @return a SignServiceErrorException
   */
  private SignServiceErrorException mapAuthenticationError(final UserAuthenticationException e) {
    if (e.getErrorCode() == AuthenticationErrorCode.USER_CANCEL) {
      return new SignServiceErrorException(new SignServiceError(SignServiceErrorCode.AUTHN_USER_CANCEL));
    }
    else if (e.getErrorCode() == AuthenticationErrorCode.UNSUPPORTED_AUTHNCONTEXT) {
      return new SignServiceErrorException(new SignServiceError(SignServiceErrorCode.AUTHN_UNSUPPORTED_AUTHNCONTEXT));
    }
    else if (e.getErrorCode() == AuthenticationErrorCode.MISMATCHING_IDENTITY_ATTRIBUTES) {
      return new SignServiceErrorException(
          new SignServiceError(SignServiceErrorCode.AUTHN_USER_MISMATCH, null, e.getMessage()));
    }
    else {
      return new SignServiceErrorException(
          new SignServiceError(SignServiceErrorCode.AUTHN_FAILURE, null, e.getMessage()));
    }
  }

  /**
   * The "complete authentication" method is invoked after the authentication handler has reported a successful user
   * authentication. At this point we know that the handler has asserted that the required user attributes were
   * presented during the authentication, but we still need to check some additional things. This includes asserting
   * that the signature message was displayed (if required) and making sure that we received attributes from the
   * authentication needed to create the certificate contents.
   *
   * @param httpRequest the HTTP request
   * @param authnResult the authentication result
   * @param context the engine context
   * @throws UnrecoverableSignServiceException for unrecoverable errors
   * @throws SignServiceErrorException for errors that should be passed back to the client (as an error response)
   */
  protected void completeAuthentication(
      final HttpServletRequest httpRequest, final AuthenticationResult authnResult, final EngineContext context)
      throws UnrecoverableSignServiceException, SignServiceErrorException {

    log.debug("{}: Authentication result: {} [id: '{}', request-id: '{}']",
        this.getName(), authnResult,
        context.getId(), context.getSignRequest().getRequestId());

    // First we need to assert that the sign message really was displayed by the authentication
    // service (if this was requested).
    //
    final SignRequestMessage signRequest = context.getSignRequest();
    if (Optional.ofNullable(signRequest.getSignMessage()).map(SignMessage::getMustShow).orElse(false)
        && !authnResult.signMessageDisplayed()) {
      log.info("{}: No sign message was displayed to the user during authentication - "
          + "this was required by client [id: '{}', request-id: '{}']",
          this.getName(), context.getId(), signRequest.getRequestId());

      throw new SignServiceErrorException(new SignServiceError(SignServiceErrorCode.AUTHN_SIGNMESSAGE_NOT_DISPLAYED));
    }

    // Assert that we got all the attributes needed to create the certificate contents ...
    //
    final SigningCertificateRequirements certRequirements = signRequest.getSigningCertificateRequirements();
    if (certRequirements != null) {
      // Note: This implementation does not handle any pre-configured policies, so we assume that
      // all mappings between certificate contents and attributes are provided in the request.

      // These are the attributes that were issued during the authentication phase ...
      final List<IdentityAttribute<?>> issuedAttributes = authnResult.getAssertion().getIdentityAttributes();

      for (final CertificateAttributeMapping m : certRequirements.getAttributeMappings()) {
        // We need to find an attribute for all mappings that are required and that do not
        // have a default value ...
        //
        if (m.getDestination().isRequired() && m.getDestination().getDefaultValue() == null) {
          // At least one of the source attributes must be among the issued identity attributes ...
          //
          final boolean exists = m.getSources().stream()
              .filter(i -> issuedAttributes.stream().filter(
                  a -> a.getIdentifier().equals(i.getIdentifier())).findFirst().isPresent())
              .findFirst()
              .isPresent();
          if (!exists) {
            final String msg = String.format("None of the source attributes for certificate attribute '%s' "
                + "was received from user authentication", m.getDestination().getIdentifier());
            log.info("{}: {} [id: '{}', request-id: '{}']",
                this.getName(), msg, context.getId(), signRequest.getRequestId());

            // TODO: Which error code to use?
            throw new SignServiceErrorException(new SignServiceError(
                SignServiceErrorCode.REQUEST_INCORRECT, "Attribute missing", msg));
          }
        }
      }
    }

    // Audit log
    //
    this.engineConfiguration.getAuditLogger().auditLog(AuditEventIds.EVENT_ENGINE_USER_AUTHENTICATED, (b) -> b
        .parameter("engine-name", this.getName())
        .parameter("client-id", this.engineConfiguration.getClientConfiguration().getClientId())
        .parameter("request-id", signRequest.getRequestId())
        .parameter("authn-id", authnResult.getAssertion().getIdentifier())
        .parameter("authn-server", authnResult.getAssertion().getIssuer())
        .parameter("authn-instant", authnResult.getAssertion().getAuthnInstant().toString())
        .parameter("authn-context-id", authnResult.getAssertion().getAuthnContext().getIdentifier())
        .parameter("authn-sign-message-displayed", authnResult.signMessageDisplayed() ? "true" : "false")
        .build());

    // Save authentication information for later ...
    //
    context.putIdentityAssertion(authnResult.getAssertion());
    context.putSignMessageDisplayed(authnResult.signMessageDisplayed());
  }

  /**
   * Method that is invoked to create an error response message that is to be sent back to the client.
   *
   * @param httpRequest the servlet request
   * @param context the engine context
   * @param error the representation of the error to send
   * @return a HttpRequestMessage to return back to the application
   * @throws UnrecoverableSignServiceException for unrecoverable errors
   */
  protected HttpRequestMessage sendErrorResponse(
      final HttpServletRequest httpRequest, final EngineContext context, final SignServiceError error)
      throws UnrecoverableSignServiceException {

    try {
      final ProtocolHandler handler = this.engineConfiguration.getProtocolHandler();

      // Translate the error into the protocol specific error representation.
      //
      final SignResponseResult errorResult = handler.translateError(error);

      // Use the protocol handler to create a response message and assign the error.
      //
      final SignResponseMessage responseMessage = handler.createSignResponseMessage(
          context.getContext(), context.getSignRequest());
      responseMessage.setSignResponseResult(errorResult);

      // Check if the error response needs to be signed, and if so, sign the message.
      //
      if (responseMessage.getProcessingRequirements()
          .getResponseSignatureRequirement() == SignatureRequirement.REQUIRED) {
        responseMessage.sign(this.engineConfiguration.getSignServiceCredential());
      }

      // Let the protocol handler encode the return message.
      //
      final HttpRequestMessage result = handler.encodeResponse(responseMessage, context.getContext());

      // Audit log
      //
      this.engineConfiguration.getAuditLogger().auditLog(AuditEventIds.EVENT_ENGINE_SIGNATURE_OPERATION_FAILURE,
          (b) -> b
              .parameter("engine-name", this.getName())
              .parameter("client-id", this.engineConfiguration.getClientConfiguration().getClientId())
              .parameter("request-id",
                  Optional.ofNullable(context.getSignRequest()).map(SignRequestMessage::getRequestId)
                      .orElseGet(() -> "-"))
              .parameter("error-code", error.getErrorCode().name())
              .parameter("error-message", error.getMessage())
              .parameter("detailed-error-message", Optional.ofNullable(error.getDetailedMessage()).orElseGet(() -> "-"))
              .build());

      // Clear the sign service context ...
      //
      this.removeContext(httpRequest);

      return result;
    }
    catch (final SignatureException e) {
      log.info("{}: Failed to sign error response message - {}. [id: '{}']",
          this.getName(), e.getMessage(), context.getId(), e);
      throw new UnrecoverableSignServiceException(
          UnrecoverableErrorCodes.INTERNAL_ERROR, "Failed to sign response message", e);
    }
    catch (final ProtocolException e) {
      log.info("{}: Failed to encode error response message - {}. [id: '{}']",
          this.getName(), e.getMessage(), context.getId(), e);
      throw new UnrecoverableSignServiceException(
          UnrecoverableErrorCodes.INTERNAL_ERROR, "Failed to encode response message", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean canProcess(@Nonnull final HttpServletRequest httpRequest) {
    AuditLoggerSingleton.init(this.engineConfiguration.getAuditLogger());

    if (this.isSignRequestEndpoint(httpRequest)) {
      // Process SignRequest
      return true;
    }
    else if (this.engineConfiguration.getAuthenticationHandler().canProcess(httpRequest, null)) {
      // Resume authn
      return true;
    }
    else {
      // Request to a HTTP resource
      return this.engineConfiguration.getHttpResourceProviders().stream()
          .filter(p -> p.supports(httpRequest))
          .findFirst()
          .isPresent();
    }
  }

  /**
   * Predicate that tells if the supplied HTTP request is sent to an endpoint where the engine expects to receive
   * SignRequest messages on.
   *
   * @param httpRequest the HTTP request
   * @return true if the request is sent to a SignRequest endpoint and false otherwise
   */
  protected boolean isSignRequestEndpoint(final HttpServletRequest httpRequest) {
    final String request = httpRequest.getRequestURI();
    return this.engineConfiguration.getProcessingPaths().stream()
        .anyMatch(p -> p.equalsIgnoreCase(request));
  }

  /**
   * Given a HTTP request the method gets an {@link EngineContext}.
   *
   * @param httpRequest the HTTP request
   * @return an engine context
   */
  protected EngineContext getContext(final HttpServletRequest httpRequest) {
    final SignServiceSession session = this.sessionHandler.getSession(httpRequest);
    SignServiceContext context = session.getSignServiceContext();
    if (context == null) {
      context = EngineContext.createSignServiceContext();
    }
    session.setSignServiceContext(context);
    return new EngineContext(context);
  }

  /**
   * Given a HTTP request the method removed the current SignService context.
   *
   * @param httpRequest the HTTP request
   */
  protected void removeContext(final HttpServletRequest httpRequest) {
    final SignServiceSession session = this.sessionHandler.getSession(httpRequest, false);
    if (session != null) {
      session.removeSignServiceContext();
    }
  }

  /**
   * Resets the SignService context. Needed if we abandon an already started context.
   *
   * @param httpRequest the HTTP request
   * @return a new engine context
   */
  protected EngineContext resetContext(final HttpServletRequest httpRequest) {
    final SignServiceContext context = EngineContext.createSignServiceContext();
    final SignServiceSession session = this.sessionHandler.getSession(httpRequest);
    session.setSignServiceContext(context);
    return new EngineContext(context);
  }

  /**
   * Assigns the {@link SignRequestMessageVerifier} to use when verifying a {@link SignRequestMessage}.
   *
   * @param signRequestMessageVerifier verifier instance
   */
  public void setSignRequestMessageVerifier(final SignRequestMessageVerifier signRequestMessageVerifier) {
    this.signRequestMessageVerifier = signRequestMessageVerifier;
  }

}
