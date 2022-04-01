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
import se.swedenconnect.signservice.authn.AuthenticationResult;
import se.swedenconnect.signservice.authn.AuthenticationResultChoice;
import se.swedenconnect.signservice.authn.UserAuthenticationException;
import se.swedenconnect.signservice.core.http.HttpRequestMessage;
import se.swedenconnect.signservice.core.http.HttpResourceProvider;
import se.swedenconnect.signservice.engine.SignServiceEngine;
import se.swedenconnect.signservice.engine.SignServiceError;
import se.swedenconnect.signservice.engine.UnrecoverableErrorCodes;
import se.swedenconnect.signservice.engine.UnrecoverableSignServiceException;
import se.swedenconnect.signservice.protocol.ProtocolException;
import se.swedenconnect.signservice.protocol.SignRequestMessage;
import se.swedenconnect.signservice.session.SignServiceSession;
import se.swedenconnect.signservice.storage.MessageReplayException;

/**
 * The default implementation of the {@link SignServiceEngine} API.
 */
@Slf4j
public class DefaultSignServiceEngine implements SignServiceEngine {

  /** The engine's configuration. */
  private final EngineConfiguration engineConfiguration;

  /** The sign message verifier. */
  private SignRequestMessageVerifier signRequestMessageVerifier;

  /**
   * Constructor.
   *
   * @param engineConfiguration the engine configuration
   */
  public DefaultSignServiceEngine(final EngineConfiguration engineConfiguration) {
    this.engineConfiguration = Objects.requireNonNull(engineConfiguration, "engineConfiguration must not be null");
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

    // Get the context and check our state ...
    //
    final EngineContext context = this.getContext(httpRequest);
    final SignOperationState state = context.getState();

    if (state == SignOperationState.NEW) {
      // Initiate new operation ...
      return this.processSignRequest(httpRequest, context);
    }
    else if (state == SignOperationState.AUTHN_ONGOING) {
      // Resume authentication ...
      return this.resumeAuthentication(httpRequest, context);
    }
    else {
      // State error
      log.info("{}: State error - Can not process request '{}'",
          this.engineConfiguration.getName(), httpRequest.getRequestURI());

      throw new UnrecoverableSignServiceException(UnrecoverableErrorCodes.STATE_ERROR, "State error");
    }
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

    // Assert that the request was received on the expected endpoint ...
    //
    if (!httpRequest.getRequestURI().startsWith(this.engineConfiguration.getProcessingPath())) {
      log.info("{}: Unexpected path '{}' - expected '{}'",
          this.engineConfiguration.getName(), httpRequest.getRequestURI(),
          this.engineConfiguration.getProcessingPath());

      throw new UnrecoverableSignServiceException(
          UnrecoverableErrorCodes.NOT_FOUND, "Not found - " + httpRequest.getRequestURI());
    }

    try {
      // Decode the incoming request ...
      //
      final SignRequestMessage signRequestMessage = this.decodeMessage(httpRequest, context);

      // Make sure that this is not a replay attack ...
      //
      try {
        this.engineConfiguration.getMessageReplayChecker().checkReplay(signRequestMessage.getRequestId());
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

      // Init authentication

      // Complete authentication

      // Generate key and cert

      // Sign

      // Encode response
    }
    catch (final SignServiceErrorException e) {
      // TODO: log
      return this.sendErrorResponse(httpRequest, context, e.getError());
    }

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

  protected HttpRequestMessage resumeAuthentication(
      final HttpServletRequest httpRequest, final EngineContext context) throws UnrecoverableSignServiceException {

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
        return this.completeAuthentication(httpRequest, authnChoice.getAuthenticationResult(), context);
      }
    }
    catch (final UserAuthenticationException e) {
      // TODO: Translate the exception into a generic error ...
      return null;
    }
  }

  protected HttpRequestMessage completeAuthentication(
      final HttpServletRequest httpRequest, final AuthenticationResult authnResult,
      final EngineContext context) throws UnrecoverableSignServiceException {

    return null;
  }

  protected HttpRequestMessage sendErrorResponse(
      final HttpServletRequest httpRequest, final EngineContext context, final SignServiceError error)
      throws UnrecoverableSignServiceException {

    return null;
  }

  /** {@inheritDoc} */
  @Override
  public boolean canProcess(final HttpServletRequest httpRequest) {
    if (httpRequest.getRequestURI().startsWith(this.engineConfiguration.getProcessingPath())) {
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
   * Given a HTTP request the method gets an {@link EngineContext}.
   *
   * @param httpRequest the HTTP request
   * @return an engine context
   */
  protected EngineContext getContext(final HttpServletRequest httpRequest) {
    final SignServiceSession session = this.engineConfiguration.getSessionHandler().getSession(httpRequest);
    return new EngineContext(session.getSignServiceContext());
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
