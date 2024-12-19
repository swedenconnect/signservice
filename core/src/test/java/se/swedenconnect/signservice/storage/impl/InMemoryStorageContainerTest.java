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
package se.swedenconnect.signservice.storage.impl;

import java.time.Duration;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for InMemoryStorageContainer.
 */
public class InMemoryStorageContainerTest {

  @Test
  public void testOperations() {
    final InMemoryStorageContainer<Long> container = new InMemoryStorageContainer<>("storage");
    Assertions.assertEquals("storage", container.getName());
    container.put("id1", Long.valueOf("1"));
    Assertions.assertEquals(Long.valueOf("1"), container.get("id1"));
    container.remove("id1");
    Assertions.assertNull(container.get("id1"));

    // Has no effect since we don't expire elements
    container.cleanup();
  }

  // Doesn't run well when running in GitHub action
  public void testExpiredAndThreshold() throws Exception {
    final InMemoryStorageContainer<Long> container = new InMemoryStorageContainer<>("storage");
    container.setCleanupThreshold(20);
    container.setElementLifetime(Duration.ofMillis(100));
    Assertions.assertEquals(Duration.ofMillis(100), container.getElementLifetime());

    for (int i = 0; i < 25; i++) {
      container.put("id" + i, Long.valueOf(i));
    }
    Thread.sleep(100);
    // id0 should now be expired
    Assertions.assertNull(container.get("id0"));

    // We are over the threshold, clean up
    container.put("id26", Long.valueOf(26));

    for (int i = 0; i < 25; i++) {
      Assertions.assertNull(container.get("id" + i));
    }
    Assertions.assertNotNull(container.get("id26"));
  }

}
