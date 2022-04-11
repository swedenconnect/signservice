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
package se.swedenconnect.signservice.api.engine.session;

import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.signservice.session.SignServiceContext;
import se.swedenconnect.signservice.session.impl.DefaultSignServiceContext;

/**
 * The {@code EngineContext} is a wrapper for the {@link SignServiceContext} that declares methods for context elements
 * that are used by the SignService engine.
 */
@Slf4j
public class EngineContext {

  /** Prefix for all context values. */
  private static final String PREFIX = EngineContext.class.getPackageName();

  /** Key for storing the state. */
  private static final String CONTEXT_STATE_KEY = PREFIX + ".State";

  /** The wrapped context. */
  private SignServiceContext context;

  /**
   * Constructor.
   *
   * @param context the context that we wrap
   */
  public EngineContext(final SignServiceContext context) {
    this.context = Objects.requireNonNull(context, "context must not be null");
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
    return this.context;
  }

  /**
   * Gets the operation state.
   *
   * @return the state
   */
  public SignOperationState getState() {
    return Optional.ofNullable(this.context.get(CONTEXT_STATE_KEY, SignOperationState.class))
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
    if (currentState == SignOperationState.SIGNING && newState == SignOperationState.AUTHN_ONGOING) {
      throw new IllegalStateException("Illegal state transition - Cannot go backwards in state transitions");
    }
    this.context.put(CONTEXT_STATE_KEY, Objects.requireNonNull(newState, "Supplied state must not be null"));
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
    context.put(CONTEXT_STATE_KEY, SignOperationState.NEW);
    return context;
  }

}
