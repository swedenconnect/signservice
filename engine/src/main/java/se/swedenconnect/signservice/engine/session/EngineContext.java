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
package se.swedenconnect.signservice.engine.session;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.signservice.authn.IdentityAssertion;
import se.swedenconnect.signservice.context.DefaultSignServiceContext;
import se.swedenconnect.signservice.context.SignServiceContext;
import se.swedenconnect.signservice.protocol.SignRequestMessage;

/**
 * The {@code EngineContext} is a wrapper for the {@link SignServiceContext} that declares methods for context elements
 * that are used by the SignService engine.
 */
@Slf4j
public class EngineContext {

  /** Prefix for all context values. */
  private static final String PREFIX = EngineContext.class.getPackageName();

  /** Key for storing the state. */
  private static final String STATE_KEY = PREFIX + ".State";

  /** Key for storing the SignRequest message. */
  private static final String SIGN_REQUEST_KEY = PREFIX + ".SignRequest";

  /** Key for storing the identity assertion. */
  private static final String ASSERTION_KEY = PREFIX + ".IdentityAssertion";

  /** Key for storing whether a sign message was displayed. */
  private static final String SIGN_MESSAGE_DISPLAYED_KEY = PREFIX + ".SignMessageDisplayed";

  /** The wrapped context. */
  private SignServiceContext context;

  /**
   * Constructor.
   *
   * @param context the context that we wrap
   */
  public EngineContext(final SignServiceContext context) {
    this.context = Objects.requireNonNull(context, "context must not be null");
    if (!this.isActive()) {
      throw new IllegalStateException("Invalid context - it is not valid");
    }
  }

  /**
   * Creates and initializes a new {@link SignServiceContext} object.
   *
   * @return a SignServiceContext object
   */
  public static SignServiceContext createSignServiceContext() {
    final SignServiceContext context = new DefaultSignServiceContext(UUID.randomUUID().toString());
    log.debug("A SignServiceContext with ID '{}' was created", context.getId());

    // Initialize
    context.put(STATE_KEY, SignOperationState.NEW);
    return context;
  }

  /**
   * Marks the context as non-active, i.e., terminated.
   */
  public void terminateContext() {
    this.updateState(SignOperationState.TERMINATED);
  }

  /**
   * Will reset the context to a new context.
   */
  public void resetContext() {
    this.context = createSignServiceContext();
  }

  /**
   * Gets the ID of the wrapped SignService context.
   *
   * @return the ID
   */
  public String getId() {
    return this.context.getId();
  }

  /**
   * Gets the wrapped context.
   *
   * @return the SignService context
   */
  public SignServiceContext getContext() {
    return this.isActive() ? this.context : null;
  }

  /**
   * Gets the operation state.
   *
   * @return the state
   */
  public SignOperationState getState() {
    return Optional.ofNullable(this.context.get(STATE_KEY, SignOperationState.class))
        .orElseThrow(() -> new IllegalStateException("No SignService state available"));
  }

  /**
   * Updates the operation state.
   *
   * @param newState the new state to set
   * @throws IllegalStateException if an illegal state transition is performed
   */
  public void updateState(final SignOperationState newState) throws IllegalStateException {
    final SignOperationState currentState = this.getState();

    if (newState == SignOperationState.NEW) {
      throw new IllegalStateException("Illegal state transition - Cannot set state to NEW");
    }
    if (currentState == SignOperationState.TERMINATED && newState != SignOperationState.TERMINATED) {
      throw new IllegalStateException("Illegal state transition - State is terminated");
    }
    if (currentState == SignOperationState.SIGNING && newState == SignOperationState.AUTHN_ONGOING) {
      throw new IllegalStateException("Illegal state transition - Cannot go backwards in state transitions");
    }
    this.context.put(STATE_KEY, Objects.requireNonNull(newState, "Supplied state must not be null"));
  }

  /**
   * Adds a {@link SignRequestMessage} to the context.
   *
   * @param signRequest the SignRequest to add
   */
  public void putSignRequest(final SignRequestMessage signRequest) {
    this.context.put(SIGN_REQUEST_KEY,
        Objects.requireNonNull(signRequest, "signRequest must not be null"));
  }

  /**
   * Gets the {@link SignRequestMessage} from the context.
   *
   * @return the SignRequest
   */
  public SignRequestMessage getSignRequest() {
    return this.context.get(SIGN_REQUEST_KEY, SignRequestMessage.class);
  }

  /**
   * Adds a {@link IdentityAssertion} to the context.
   *
   * @param identityAssertion the identity assertion to add
   */
  public void putIdentityAssertion(final IdentityAssertion identityAssertion) {
    this.context.put(ASSERTION_KEY,
        Objects.requireNonNull(identityAssertion, "identityAssertion must not be null"));
  }

  /**
   * Gets the {@link IdentityAssertion} from the context.
   *
   * @return the identity assertion
   */
  public IdentityAssertion getIdentityAssertion() {
    return this.context.get(ASSERTION_KEY, IdentityAssertion.class);
  }

  /**
   * Adds whether the SignMessage was displayed.
   *
   * @param signMessageDisplayed whether SignMessage was displayed
   */
  public void putSignMessageDisplayed(final Boolean signMessageDisplayed) {
    this.context.put(SIGN_MESSAGE_DISPLAYED_KEY,
        Objects.requireNonNull(signMessageDisplayed, "signMessageDisplayed must not be null"));
  }

  /**
   * Gets whether the SignMessage was displayed.
   *
   * @return whether the SignMessage was displayed
   */
  public Boolean getSignMessageDisplayed() {
    return this.context.get(SIGN_MESSAGE_DISPLAYED_KEY, Boolean.class);
  }

  /**
   * Predicate that tells whether this context is active or not
   *
   * @return true if the context is active and false otherwise
   */
  private boolean isActive() {
    return this.getState() != SignOperationState.TERMINATED;
  }

}
