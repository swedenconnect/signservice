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
package se.swedenconnect.signservice.core;

import javax.annotation.Nonnull;

import se.swedenconnect.signservice.engine.SignServiceEngine;

/**
 * Base interface for a SignService "handler".
 * <p>
 * Handlers exist for different purposes such as user authentication, audit loggers, key and certificate handler and
 * more. A {@link SignServiceEngine} instance is configured with specific handler instances to service a client.
 * </p>
 */
public interface SignServiceHandler {

  /**
   * Gets the name of the handler.
   * <p>
   * If the handler name has not been explicitly set the "simple" class name for the handler instance must be used.
   * </p>
   *
   * @return the handler name
   */
  @Nonnull
  String getName();

}
