/*
 * MIT License
 *
 * Copyright 2022 Sweden Connect
 */
package se.swedenconnect.signservice.api.session;

import java.io.Serializable;

/**
 * The {@code SignServiceContext} holds the current context and state for an operation. It is stored
 * in the session and all modules can read and update it.
 * <p>
 * The data stored in the context is not fixed and is determined by the different modules that need
 * to handle session data.
 * </p>
 * <p>
 * The context is initialized by the SignService Engine.
 * </p>
 */
public interface SignServiceContext extends Serializable {

  /**
   * Gets the unique ID for the current operation. This ID should be included in all logs (process-
   * and audit logs).
   *
   * @return the unique ID for the operation
   */
  String getId();

  /**
   * Stores a data element in the context.
   *
   * @param <T> the type of the element
   * @param name the unique name of the element
   * @param data the element to store
   */
  <T extends Serializable> void put(final String name, final T data);

  /**
   * Gets a named data element from the context.
   *
   * @param <T> the type of the element
   * @param name the unique name of the element
   * @return the element, or null if no matching element is available
   */
  <T extends Serializable> T get(final String name);

  /**
   * Gets a named data element having a given type from the context.
   *
   * @param <T> the type of the element
   * @param name the unique name of the element
   * @param type the type of the element
   * @return the element, or null if no matching element is available
   * @throws ClassCastException if the element exists but is not of thegiven type
   */
  <T extends Serializable> T get(final String name, final Class<T> type) throws ClassCastException;

  /**
   * Removes the named element from the context.
   * <p>
   * The rationale behind this method is that a module that writes a large data element to the
   * context should be able to remove it when it os no longer needed. In this way, storing the
   * context is cheaper.
   * </p>
   *
   * @param <T> the type of the element
   * @param name the unique name of the element
   */
  <T extends Serializable> void remove(final String name);

}
