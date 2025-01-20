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
package se.swedenconnect.signservice.storage.impl;

import java.util.Objects;

import jakarta.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.signservice.storage.MessageReplayChecker;
import se.swedenconnect.signservice.storage.MessageReplayException;

/**
 * The default implementation of the {@link MessageReplayChecker} interface.
 */
@Slf4j
public class DefaultMessageReplayChecker implements MessageReplayChecker {

  /** The storage where ID:s are stored. */
  private final ReplayCheckerStorageContainer storage;

  /**
   * Constructor.
   *
   * @param storage the storage where ID:s are stored
   */
  public DefaultMessageReplayChecker(@Nonnull final ReplayCheckerStorageContainer storage) {
    this.storage = Objects.requireNonNull(storage, "storage must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public void checkReplay(@Nonnull final String id) throws MessageReplayException {
    final Long e = this.storage.get(id);
    if (e == null) {
      this.storage.put(id, System.currentTimeMillis());
      log.debug("Message replay check of ID '{}' succeeded", id);
    }
    else {
      String msg = String.format("Replay check of ID '%s' failed", id);
      log.warn(msg);
      throw new MessageReplayException(msg);
    }
  }

}
