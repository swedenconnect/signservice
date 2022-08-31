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
package se.swedenconnect.signservice.session;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

import javax.servlet.http.HttpSession;

/**
 * A representation of a session. The {@code SignServiceSession} is basically the same as {@link HttpSession}, but since
 * we don't want to get stuck in a particular session implementation, we introduce this session abstraction.
 */
public interface SignServiceSession {

  /** The name of the session object that holds the {@link SignServiceContext}. */
  String CONTEXT_NAME = SignServiceContext.class.getPackageName() + ".Context";

  /**
   * Gets the unique ID for the session.
   *
   * @return the session ID
   */
  String getId();

  /**
   * Gets a named session attribute.
   *
   * @param <T> the type
   * @param name the name of the session attribute
   * @return the attribute or null if no such attribute is available
   * @throws IllegalStateException if this method is called on an invalidated session
   */
  <T extends Serializable> T getAttribute(final String name) throws IllegalStateException;

  /**
   * Gets a named session attribute having the specified type.
   *
   * @param <T> the type
   * @param name the name of the session attribute
   * @param type the desired type of the attribute
   * @return the attribute or null if no such attribute is available
   * @throws IllegalStateException if this method is called on an invalidated session
   * @throws ClassCastException if the attribute exists but cannot be cast to the given type
   */
  <T extends Serializable> T getAttribute(final String name, final Class<T> type)
      throws IllegalStateException, ClassCastException;

  /**
   * Gets the {@link SignServiceContext} object.
   * <p>
   * This method is a utility method for easy access to the context. It corresponds to the call
   * {@code getSessionAttribute(SignServiceSession.CONTEXT_NAME, SignServiceContext.class)}.
   * </p>
   *
   * @return the SignServiceContext
   * @throws IllegalStateException if this method is called on an invalidated session
   */
  default SignServiceContext getSignServiceContext() throws IllegalStateException {
    return this.getAttribute(CONTEXT_NAME, SignServiceContext.class);
  }

  /**
   * Returns a list of all attribute names that this session holds.
   *
   * @return a list of attribute names
   * @throws IllegalStateException if this method is called on an invalidated session
   */
  List<String> getAttributeNames() throws IllegalStateException;

  /**
   * Adds a session attribute to the session.
   *
   * @param <T> the type
   * @param name the attribute name
   * @param attribute the attribute value
   * @throws IllegalStateException if this method is called on an invalidated session
   */
  <T extends Serializable> void setAttribute(final String name, final T attribute) throws IllegalStateException;

  /**
   * Adds the {@link SignServiceContext} to the session.
   * <p>
   * This method is a convenience method that corresponds to the call
   * {@code setAttribute(SignServiceSession.CONTEXT_NAME, context)}.
   * </p>
   *
   * @param context the context to add
   * @throws IllegalStateException if this method is called on an invalidated session
   */
  default void setSignServiceContext(final SignServiceContext context) throws IllegalStateException {
    this.setAttribute(CONTEXT_NAME, context);
  }

  /**
   * Removes the named attribute from the session.
   *
   * @param name the attribute name
   * @throws IllegalStateException if this method is called on an invalidated session
   */
  void removeAttribute(final String name) throws IllegalStateException;

  /**
   * This method is a convenience method that corresponds to the call
   * {@code removeAttribute(SignServiceSession.CONTEXT_NAME)}.
   * </p>
   *
   * @throws IllegalStateException if this method is called on an invalidated session
   */
  default void removeSignServiceContext() throws IllegalStateException {
    this.removeAttribute(CONTEXT_NAME);
  }

  /**
   * Invalidates this session then unbinds any objects bound to it.
   *
   * @exception IllegalStateException if this method is called on an already invalidated session
   */
  public void invalidate();

  /**
   * Tells when this session was created.
   *
   * @return an Instant
   * @throws IllegalStateException if this method is called on an invalidated session
   */
  Instant getCreationTime() throws IllegalStateException;

  /**
   * Gets the last time the client sent a request associated with this session.
   * <p>
   * Actions that your application takes, such as getting or setting a value associated with the session, do not affect
   * the access time.
   * </p>
   *
   * @return an Instant
   * @throws IllegalStateException if this method is called on an invalidated session
   */
  Instant getLastAccessedTime() throws IllegalStateException;

}
