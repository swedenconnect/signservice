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
package se.swedenconnect.signservice.storage;

/**
 * Interface for protecting against message replay attacks.
 */
public interface MessageReplayChecker {

  /**
   * Checks if the supplied message ID already has been processed within the time the replay checker keeps the processed
   * items in its cache.
   * <p>
   * If the message ID is not present in its cache it will be stored.
   * </p>
   *
   * @param id the message ID
   * @throws MessageReplayException if ID is present in the replay cache
   */
  void checkReplay(final String id) throws MessageReplayException;

}
