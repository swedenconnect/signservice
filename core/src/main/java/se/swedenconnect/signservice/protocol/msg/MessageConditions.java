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
package se.swedenconnect.signservice.protocol.msg;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.Serializable;
import java.time.Instant;

/**
 * Represents "conditions" that appears in a SignService message.
 */
public interface MessageConditions extends Serializable {

  /**
   * Tells that the message must not be regarded as valid before this instant.
   *
   * @return not before instant
   */
  @Nullable
  Instant getNotBefore();

  /**
   * Tells that the message must not be regarded as valid after this instant.
   *
   * @return not after instant
   */
  @Nullable
  Instant getNotAfter();

  /**
   * Checks whether the supplied instant meets the not-before and not-after conditions.
   * <p>
   * In case not-before or not-after are not set, it means "accept".
   * </p>
   *
   * @param instant the instant to test
   * @return true if the supplied instant meets the criteria and false otherwise
   */
  boolean isWithinRange(@Nonnull final Instant instant);

}
