/*
 * MIT License
 *
 * Copyright 2022 Sweden Connect
 */
package se.swedenconnect.signservice.core.session;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import se.swedenconnect.signservice.api.session.SignServiceContext;

/**
 * Default implementation of the {@link SignServiceContext} interface.
 */
public class DefaultSignServiceContext implements SignServiceContext {

  /** For serializing. */
  private static final long serialVersionUID = -5637851951212011897L;

  /** The context ID. */
  private final String id;

  /** The context data. */
  private final Map<String, Serializable> data = new HashMap<>();

  /**
   * Constructor.
   *
   * @param id the context ID
   */
  public DefaultSignServiceContext(final String id) {
    this.id = id;
  }

  /** {@inheritDoc} */
  @Override
  public String getId() {
    return this.id;
  }

  /** {@inheritDoc} */
  @Override
  public <T extends Serializable> void put(final String name, final T data) {
    this.data.put(name, data);
  }

  /** {@inheritDoc} */
  @Override
  @SuppressWarnings("unchecked")
  public <T extends Serializable> T get(final String name) {
    return (T) this.data.get(name);
  }

  /** {@inheritDoc} */
  @Override
  public <T extends Serializable> T get(final String name, final Class<T> type)
      throws ClassCastException {

    return Optional.ofNullable(this.data.get(name)).map(type::cast).orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  public <T extends Serializable> void remove(final String name) {
    this.data.remove(name);
  }

}
