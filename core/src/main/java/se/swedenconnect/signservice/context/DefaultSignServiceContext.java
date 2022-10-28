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
package se.swedenconnect.signservice.context;

import java.io.Serializable;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.commons.lang.SerializationUtils;

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
  public DefaultSignServiceContext(@Nonnull final String id) {
    this.id = Objects.requireNonNull(id, "id must not be null");
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getId() {
    return this.id;
  }

  /** {@inheritDoc} */
  @Override
  public <T extends Serializable> void put(@Nonnull final String name, @Nullable final T data) {
    this.data.put(Objects.requireNonNull(name, "name must not be null"), data);
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  @SuppressWarnings("unchecked")
  public <T extends Serializable> T get(@Nonnull final String name) {
    return (T) this.data.get(Objects.requireNonNull(name, "name must not be null"));
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public <T extends Serializable> T get(@Nonnull final String name, @Nonnull final Class<T> type)
      throws ClassCastException {
    return Optional.ofNullable(this.data.get(Objects.requireNonNull(name, "name must not be null")))
        .map(type::cast)
        .orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  public <T extends Serializable> void remove(@Nonnull final String name) {
    this.data.remove(Objects.requireNonNull(name, "name must not be null"));
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String serialize() {
    return Base64.getEncoder().encodeToString(SerializationUtils.serialize(this));
  }

  /**
   * Deserializes an encoding to a {@code DefaultSignServiceContext} object.
   *
   * @param encoding the string encoding
   * @return a DefaultSignServiceContext object
   */
  @Nonnull
  public static DefaultSignServiceContext deserialize(@Nonnull final String encoding) {
    return (DefaultSignServiceContext) SerializationUtils.deserialize(
        Base64.getDecoder().decode(Objects.requireNonNull(encoding, "encoding must not be null")));
  }

}
