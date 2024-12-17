/*
 * Copyright 2022-2024 Sweden Connect
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
package se.swedenconnect.signservice.core.types;

import jakarta.annotation.Nullable;

/**
 * Base class for representing a Choice between two objects, where one is set and the other is {@code null}.
 *
 * @param <F> type for the first object
 * @param <S> type for the second object
 */
public class Choice<F, S> {

  /** The first object. */
  private final F first;

  /** The second object. */
  private final S second;

  /**
   * Constructor where one parameter must be null and the other non-null.
   *
   * @param first the first object
   * @param second the second object
   */
  public Choice(final F first, final S second) {
    this.first = first;
    this.second = second;
    if (this.first != null && this.second != null) {
      throw new IllegalArgumentException("Both first and second are non null - not allowed in a Choice");
    }
    if (this.first == null && this.second == null) {
      throw new IllegalArgumentException("Both first and second are null - not allowed in a Choice");
    }
  }

  /**
   * Gets the first choice.
   *
   * @return the first choice or null
   */
  @Nullable
  public F getFirst() {
    return this.first;
  }

  /**
   * Gets the second choice.
   *
   * @return the second choice or null
   */
  @Nullable
  public S getSecond() {
    return this.second;
  }

}
