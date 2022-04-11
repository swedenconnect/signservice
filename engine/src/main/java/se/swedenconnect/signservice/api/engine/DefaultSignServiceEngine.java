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
package se.swedenconnect.signservice.api.engine;

import java.io.IOException;
import java.util.Objects;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.signservice.api.engine.config.EngineConfiguration;
import se.swedenconnect.signservice.api.engine.impl.DefaultSignRequestMessageVerifier;
import se.swedenconnect.signservice.api.engine.session.EngineContext;
import se.swedenconnect.signservice.api.engine.session.SignOperationState;
import se.swedenconnect.signservice.authn.AuthenticationErrorCode;
import se.swedenconnect.signservice.authn.AuthenticationResult;
import se.swedenconnect.signservice.authn.AuthenticationResultChoice;
import se.swedenconnect.signservice.authn.UserAuthenticationException;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;
import se.swedenconnect.signservice.core.http.HttpResourceProvider;
import se.swedenconnect.signservice.engine.SignServiceEngine;
import se.swedenconnect.signservice.engine.SignServiceError;
import se.swedenconnect.signservice.engine.SignServiceErrorCode;
import se.swedenconnect.signservice.engine.UnrecoverableErrorCodes;
import se.swedenconnect.signservice.engine.UnrecoverableSignServiceException;
import se.swedenconnect.signservice.protocol.ProtocolException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.protocol.msg.AuthnRequirements;
import se.swedenconnect.signservice.session.SessionHandler;
import se.swedenconnect.signservice.session.SignServiceContext;
import se.swedenconnect.signservice.session.SignServiceSession;
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

  /**
   * Constructor.
   *
   * @param engineConfiguration the engine configuration
   * @param sessionHandler the session handler to use
   * @param messageReplayChecker the message replay checker
   */
  public DefaultSignServiceEngine(final EngineConfiguration engineConfiguration,
      final SessionHandler sessionHandler, final MessageReplayChecker messageReplayChecker) {
    this.engineConfiguration = Objects.requireNonNull(engineConfiguration, "engineConfiguration must not be null");
    this.sessionHandler = Objects.requireNonNull(sessionHandler, "sessionHandler must not be null");
    this.messageReplayChecker = Objects.requireNonNull(messageReplayChecker, "messageReplayChecker must not be null");
  }

  /**
   * Initializes the engine bean.
   *
   * @throws Exception for init errors
   */
  @PostConstruct
  public void init() throws Exception {
    if (this.signRequestMessageVerifier == null) {
      log.debug("{}: Setting default signRequestMessageVerifier to {}",
          this.engineConfiguration.getName(), DefaultSignRequestMessageVerifier.class.getSimpleName());
      this.signRequestMessageVerifier = new DefaultSignRequestMessageVerifier();
    }
  }

  /** {@inheritDoc} */
  @Override
  public HttpRequestMessage processRequest(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse)
      throws UnrecoverableSignServiceException {

    log.debug("{}: Received request [path: '{}', client-ip: '{}']",
        this.engineConfiguration.getName(), httpRequest.getRequestURI(), httpRequest.getRemoteAddr());

    // Before processing the request, check if it is a request for an HTTP resource ...
    //
    final HttpResourceProvider resourceProvider = this.engineConfiguration.getHttpResourceProviders().stream()
        .filter(p -> p.supports(httpRequest))
        .findFirst()
        .orElse(null);
    if (resourceProvider != null) {
      try {
        log.debug("{}: Getting resource ... [path: '{}']",
            this.engineConfiguration.getName(), httpRequest.getRequestURI());
        resourceProvider.getResource(httpRequest, httpResponse);
        return null;
      }
      catch (final IOException e) {
        log.info("{}: Error getting HTTP resource '{}' - {}",
            this.engineConfiguration.getName(), httpRequest.getRequestURI(), e.getMessage(), e);
        throw new UnrecoverableSignServiceException(
            UnrecoverableErrorCodes.HTTP_GET_ERROR, "Failed to get resource", e);
      }
    }

    // Based on the context state and the URL on which we received the request do dispatching ...
    //
    EngineContext context = this.getContext(httpRequest);

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
        log.info(
            "{}: Abandoning ongoing operation - A new SignRequest has been received in the same session [id: '{}']",
            this.engineConfiguration.getName(), context.getId());

        context = this.resetContext(httpRequest);
        log.info("{}: New context has been created [id: '{}']", this.engineConfiguration.getName(), context.getId());

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
        this.engineConfiguration.getName(), context.getState(), httpRequest.getRequestURI(), context.getId());

    throw new UnrecoverableSignServiceException(UnrecoverableErrorCodes.STATE_ERROR, "State error");
  }

  /**
   * Processes a new sign request message.
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
            this.engineConfiguration.getName(), signRequestMessage.getRequestId(), context.getId());

        throw new UnrecoverableSignServiceException(
            UnrecoverableErrorCodes.REPLAY_ATTACK, "Message is already being processed");
      }

      // Verify sign request message ...
      //
      this.signRequestMessageVerifier.verifyMessage(signRequestMessage, this.engineConfiguration, context);

      // OK, the SignRequest is accepted. Let's save it in the context for future use ...
      //
      context.putSignRequest(signRequestMessage);

      // Init authentication ...
      //
      final AuthenticationResultChoice authnResult = this.initAuthentication(httpRequest, signRequestMessage, context);
      if (authnResult.getHttpRequestMessage() != null) {
        log.debug("{}: Authentication handler ({}) directing user for authentication [id: '{}', request-id: '{}']",
            this.engineConfiguration.getName(), this.engineConfiguration.getAuthenticationHandler().getName(),
            context.getId(), signRequestMessage.getRequestId());

        return authnResult.getHttpRequestMessage();
      }
      else {
        // Proceed
        return this.finalizeSignRequest(httpRequest, authnResult.getAuthenticationResult(), context);
      }

    }
    catch (final SignServiceErrorException e) {
      // TODO: log
      return this.sendErrorResponse(httpRequest, context, e.getError());
    }
  }

  protected HttpRequestMessage finalizeSignRequest(
      final HttpServletRequest httpRequest, final AuthenticationResult authnResult, final EngineContext context)
      throws UnrecoverableSignServiceException {

    // Complete authentication

    // Generate key and cert

    // Sign

    // Encode response

    return null;
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
          this.engineConfiguration.getName(), context.getId());

      final SignRequestMessage requestMessage = this.engineConfiguration.getProtocolHandler()
          .decodeRequest(httpRequest, context.getContext());

      log.debug("{}: Successfully decoded incoming sign request message. [id: '{}', request-id: '{}']",
          this.engineConfiguration.getName(), context.getId(), requestMessage.getRequestId());
      if (log.isTraceEnabled()) {
        log.trace("{}: [id: '{}'] {}",
            this.engineConfiguration.getName(), context.getId(), requestMessage.getLogString(true));
      }

      return requestMessage;
    }
    catch (final ProtocolException e) {
      log.info("{}: Failed to decode incoming sign request - {}. [id: '{}']",
          this.engineConfiguration.getName(), e.getMessage(), context.getId(), e);
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
        this.engineConfiguration.getName(), context.getId(), signRequest.getRequestId());

    try {
      // TODO: The authentication requirements may also be controlled by a policy ...
      final AuthnRequirements reqs = signRequest.getAuthnRequirements();

      return this.engineConfiguration.getAuthenticationHandler().authenticate(
          reqs, signRequest.getSignMessage(), context.getContext());
    }
    catch (final UserAuthenticationException e) {
      log.info("{}: Authentication error: {} - {} [id: '{}', request-id: '{}']", this.engineConfiguration.getName(),
          e.getErrorCode(), e.getMessage(), context.getId(), signRequest.getRequestId());

      throw this.mapAuthenticationError(e);
    }
  }

  protected HttpRequestMessage resumeAuthentication(
      final HttpServletRequest httpRequest, final EngineContext context)
      throws UnrecoverableSignServiceException, SignServiceErrorException {

    // Assert that the request was received on a correct endpoint ...
    //
    if (!this.engineConfiguration.getAuthenticationHandler().canProcess(httpRequest)) {
      log.info("{}: Unexpected path '{}'", this.engineConfiguration.getName(), httpRequest.getRequestURI());

      throw new UnrecoverableSignServiceException(
          UnrecoverableErrorCodes.NOT_FOUND, "Not found - " + httpRequest.getRequestURI());
    }

    try {
      final AuthenticationResultChoice authnChoice = this.engineConfiguration.getAuthenticationHandler()
          .resumeAuthentication(httpRequest, context.getContext());

      if (authnChoice.getHttpRequestMessage() != null) {
        // OK, it seems like the authentication scheme redirects the user several time to an external service. Lets,
        // direct the user again.
        return authnChoice.getHttpRequestMessage();
      }
      else {
        // Authentication is complete.
        return this.finalizeSignRequest(httpRequest, authnChoice.getAuthenticationResult(), context);
      }
    }
    catch (final UserAuthenticationException e) {
      log.info("{}: Authentication error: {} - {} [id: '{}', request-id: '{}']", this.engineConfiguration.getName(),
          e.getErrorCode(), e.getMessage(), context.getId(), context.getSignRequest().getRequestId());

      throw this.mapAuthenticationError(e);
    }
  }

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

  protected void completeAuthentication(
      final HttpServletRequest httpRequest, final AuthenticationResult authnResult, final EngineContext context)
      throws UnrecoverableSignServiceException {

    // Check if sign message was displayed ...

    // Audit log

    // Save user attributes for later ...
  }

  protected HttpRequestMessage sendErrorResponse(
      final HttpServletRequest httpRequest, final EngineContext context, final SignServiceError error)
      throws UnrecoverableSignServiceException {

    return null;
  }

  /** {@inheritDoc} */
  @Override
  public boolean canProcess(final HttpServletRequest httpRequest) {
    if (this.isSignRequestEndpoint(httpRequest)) {
      // Process SignRequest
      return true;
    }
    else if (this.engineConfiguration.getAuthenticationHandler().canProcess(httpRequest)) {
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
    for (final String path : this.engineConfiguration.getProcessingPaths()) {
      if (httpRequest.getRequestURI().startsWith(path)) {
        return true;
      }
    }
    return false;
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
