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
package se.swedenconnect.signservice.storage;

import java.io.Serializable;
import java.time.Duration;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * An interface defining generic methods for storage.
 *
 * @param <T> the types of data elements stored
 */
public interface StorageContainer<T extends Serializable> {

  /**
   * Gets the name of the storage container.
   *
   * @return the storage container name
   */
  @Nonnull
  String getName();

  /**
   * Stores a data element in the container.
   *
   * @param id the unique ID of the element
   * @param data the element to store
   */
  void put(@Nonnull final String id, @Nonnull final T data);

  /**
   * Gets a data element from the container.
   * <p>
   * Note that an expired element will never be returned.
   * </p>
   *
   * @param id the unique ID of the element
   * @return the element, or null if no matching element is available
   */
  @Nullable
  T get(@Nonnull final String id);

  /**
   * Removes an element from the container.
   *
   * @param id the unique ID of the element
   */
  void remove(final String id);

  /**
   * Gets the "lifetime" of elements held in the container. A {@code null} return value means "never expires".
   *
   * @return the lifetime, or null for eternal lifetime
   */
  @Nullable
  Duration getElementLifetime();

}
