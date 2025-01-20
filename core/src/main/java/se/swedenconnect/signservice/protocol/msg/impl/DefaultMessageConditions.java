/*
 * Copyright 2022-2025 Sweden Connect
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
package se.swedenconnect.signservice.protocol.msg.impl;

import java.io.Serial;
import java.time.Instant;
import java.util.Objects;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import se.swedenconnect.signservice.core.annotations.GeneratedMethod;
import se.swedenconnect.signservice.protocol.msg.MessageConditions;

/**
 * Default implementation of {@link MessageConditions}.
 */
public class DefaultMessageConditions implements MessageConditions {

  /** For serializing. */
  @Serial
  private static final long serialVersionUID = -1228444313739138273L;

  /** Not before condition. */
  private final Instant notBefore;

  /** Not after condition. */
  private final Instant notAfter;

  /**
   * Constructor.
   *
   * @param notBefore the not-before condition
   * @param notAfter the not-after condition
   */
  public DefaultMessageConditions(@Nullable final Instant notBefore, @Nullable final Instant notAfter) {
    this.notBefore = notBefore;
    this.notAfter = notAfter;

    if (this.notBefore != null && this.notAfter != null && this.notBefore.isAfter(this.notAfter)) {
      throw new IllegalArgumentException("notBefore can not be after notAfter");
    }
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public Instant getNotBefore() {
    return this.notBefore;
  }

  /** {@inheritDoc} */
  @Override
  @Nullable
  public Instant getNotAfter() {
    return this.notAfter;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isWithinRange(@Nonnull final Instant instant) {
    if (instant == null) {
      return false;
    }
    if (this.getNotBefore() != null && instant.isBefore(this.notBefore)) {
      return false;
    }
    if (this.getNotAfter() != null && instant.isAfter(this.notAfter)) {
      return false;
    }
    return true;
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public int hashCode() {
    return Objects.hash(this.notAfter, this.notBefore);
  }

  /** {@inheritDoc} */
  @Override
  @GeneratedMethod
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof final DefaultMessageConditions other)) {
      return false;
    }
    return Objects.equals(this.notAfter, other.notAfter) && Objects.equals(this.notBefore, other.notBefore);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format("not-before='%s', not-after='%s'", this.notBefore, this.notAfter);
  }

}
