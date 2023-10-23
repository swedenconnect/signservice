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
package se.swedenconnect.signservice.storage.impl;

import java.io.Serializable;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.storage.StorageContainer;

/**
 * An in-memory implementation of the {@link StorageContainer} interface. Should only be used if the SignService only
 * runs in one instance.
 */
public class InMemoryStorageContainer<T extends Serializable> implements StorageContainer<T> {

  /** The default the threshold for cleaning up expired entries. */
  public static final int DEFAULT_CLEANUP_THRESHOLD = 500;

  /** The container name. */
  private final String name;

  /** Tells the lifetime of stored entries. If {@code null}, elements never expires. */
  private Duration elementLifetime;

  /** The storage. */
  private Map<String, StorageEntry> storage = new ConcurrentHashMap<>();

  /** An indicator for the container size threshold when the container invokes {@link #cleanup()}. */
  private int cleanupThreshold = DEFAULT_CLEANUP_THRESHOLD;

  /**
   * Constructor.
   *
   * @param name the container name
   */
  public InMemoryStorageContainer(@Nonnull final String name) {
    this.name = Objects.requireNonNull(name, "name must not be null");
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public String getName() {
    return this.name;
  }

  /** {@inheritDoc} */
  @Override
  public void put(@Nonnull final String id, @Nonnull final T data) {
    this.storage.put(id, new StorageEntry(data));
    if (this.storage.size() >= this.cleanupThreshold) {
      this.cleanup();
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public T get(@Nonnull final String id) {
    final StorageEntry entry = this.storage.get(id);
    if (entry != null && entry.isExpired()) {
      this.remove(id);
      return null;
    }
    return Optional.ofNullable(entry).map(StorageEntry::getElement).orElse(null);
  }

  /** {@inheritDoc} */
  @Override
  public void remove(@Nonnull final String id) {
    this.storage.remove(id);
  }

  /**
   * Removes expired entries.
   */
  public void cleanup() {
    if (this.elementLifetime != null) {
      this.storage.entrySet().removeIf(e -> e.getValue().isExpired());
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public Duration getElementLifetime() {
    return this.elementLifetime;
  }

  /**
   * Assigns the lifetime of stored entries. The default is {@code null}, meaning that elements never expire.
   *
   * @param elementLifetime the lifetime
   */
  public void setElementLifetime(@Nonnull final Duration elementLifetime) {
    this.elementLifetime = elementLifetime;
  }

  /**
   * Assigns the indicator for the container size threshold when the container should invoke {@link #cleanup()}. The
   * default is {@value #DEFAULT_CLEANUP_THRESHOLD}.
   *
   * @param cleanupThreshold the threshold
   */
  public void setCleanupThreshold(final int cleanupThreshold) {
    this.cleanupThreshold = cleanupThreshold;
  }

  /**
   * Representation of a storage entry.
   */
  private class StorageEntry {

    /** The time when the entry expired. If null, it never expires. */
    private Long expires;

    /** The data element. */
    private T element;

    /**
     * Constructor.
     *
     * @param element the data element
     */
    public StorageEntry(@Nonnull final T element) {
      this.element = Objects.requireNonNull(element, "element must not be null");
      this.expires = elementLifetime != null
          ? System.currentTimeMillis() + elementLifetime.toMillis()
          : null;
    }

    /**
     * Predicate telling if this entry is expired.
     *
     * @return true if the entry is expired and false otherwise
     */
    public boolean isExpired() {
      return this.expires != null && System.currentTimeMillis() > this.expires;
    }

    /**
     * Gets the data element.
     *
     * @return the data element
     */
    @Nonnull
    public T getElement() {
      return this.element;
    }

  }

}
