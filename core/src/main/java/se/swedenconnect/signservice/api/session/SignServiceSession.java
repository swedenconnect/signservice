/*
 * MIT License
 *
 * Copyright 2022 Sweden Connect
 */
package se.swedenconnect.signservice.api.session;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import javax.servlet.http.HttpSession;

/**
 * A representation of a session. The {@code SignServiceSession} is basically the same as
 * {@link HttpSession}, but since we don't want to get stuck in a particular session implementation,
 * we introduce this session abstraction.
 */
public interface SignServiceSession {

  /** The name of the session object that holds the {@link SignServiceContext}. */
  String CONTEXT_SESSION_NAME = SignServiceContext.class.getPackageName();

  /**
   * Gets the unique ID for the session.
   *
   * @return the session ID
   */
  String getSessionId();

  /**
   * Gets a named session attribute.
   *
   * @param <T> the type
   * @param name the name of the session attribute
   * @return the attribute or null if no such attribute is available
   * @throws IllegalStateException if this method is called on an invalidated session
   */
  <T extends Serializable> T getSessionAttribute(final String name) throws IllegalStateException;

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
  <T extends Serializable> T getSessionAttribute(final String name, final Class<T> type)
      throws IllegalStateException, ClassCastException;

  /**
   * Gets the {@link SignServiceContext} object.
   * <p>
   * This method is a utility method for easy access to the context. It corresponds to the call
   * {@code getSessionAttribute(SignServiceSession.CONTEXT_SESSION_NAME, SignServiceContext.class)}.
   * </p>
   *
   * @return the SignServiceContext
   * @throws IllegalStateException if this method is called on an invalidated session
   */
  SignServiceContext getSignServiceContext() throws IllegalStateException;

  /**
   * Returns a list of all attribute names that this session holds.
   *
   * @return a list of attribute names
   * @throws IllegalStateException if this method is called on an invalidated session
   */
  List<String> getSessionAttributeNames() throws IllegalStateException;

  /**
   * Adds a session attribute to the session.
   *
   * @param <T> the type
   * @param name the attribute name
   * @param attribute the attribute value
   * @throws IllegalStateException if this method is called on an invalidated session
   */
  <T extends Serializable> void setSessionAttribute(final String name, final T attribute)
      throws IllegalStateException;

  /**
   * Adds the {@link SignServiceContext} to the session.
   * <p>
   * This method is a convinience method that corresponds to the call
   * {@code setSessionAttribute(SignServiceSession.CONTEXT_SESSION_NAME, context)}.
   * </p>
   *
   * @param context the context to add
   * @throws IllegalStateException if this method is called on an invalidated session
   */
  void setSignServiceContext(final SignServiceContext context) throws IllegalStateException;

  /**
   * Removes the named attribute from the session.
   *
   * @param name the attribute name
   * @throws IllegalStateException if this method is called on an invalidated session
   */
  void removeSessionAttribute(final String name) throws IllegalStateException;

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
   * Actions that your application takes, such as getting or setting a value associated with the
   * session, do not affect the access time.
   * </p>
   *
   * @return an Instant
   * @throws IllegalStateException if this method is called on an invalidated session
   */
  Instant getLastAccessedTime() throws IllegalStateException;



}
