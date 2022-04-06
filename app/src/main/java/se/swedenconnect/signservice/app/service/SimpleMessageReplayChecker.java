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
package se.swedenconnect.signservice.app.service;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import lombok.Setter;
import se.swedenconnect.signservice.storage.MessageReplayChecker;
import se.swedenconnect.signservice.storage.MessageReplayException;

/**
 * Simple implementation of the {@link MessageReplayChecker}. Works only if the app is running as a single instance.
 */
@Service("signservice.MessageReplayChecker")
public class SimpleMessageReplayChecker implements MessageReplayChecker {

  /** Maximum age of entries. The default is 10 minutes. */
  @Setter
  @Value("${signservice.replay.age:PT10M}")
  private Duration maxAge;

  /** The saved messages. */
  private Map<String, Instant> messages = new ConcurrentHashMap<>();

  /** {@inheritDoc} */
  @Override
  public void checkReplay(final String id) throws MessageReplayException {
    final Instant added = this.messages.get(id);
    if (added == null) {
      this.messages.put(id, Instant.now());
    }
    else if (!this.isExpired(added)) {
      throw new MessageReplayException(String.format("Message %s is already in use", id));
    }
    else {
      // Expired
      this.messages.remove(id);
    }
  }

  /**
   * Cleans expired entries.
   */
  @Scheduled(fixedDelay = 600000L)
  public synchronized void clean() {
    this.messages.entrySet().removeIf(e -> this.isExpired(e.getValue()));
  }

  /**
   * Predicate that tells if an entry is expired.
   *
   * @param instant
   *          the entry to check
   * @return true if the entry is expired and false otherwise
   */
  private boolean isExpired(final Instant instant) {
    return instant.plus(this.maxAge).isBefore(Instant.now());
  }

}
